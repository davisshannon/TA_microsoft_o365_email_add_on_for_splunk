# encoding = utf-8

import json
import datetime
import splunk.entity
import urllib
import sys
import hashlib
import base64
import re
import email
import html
import io
import cryptography
import csv
import itertools
from oletools.olevba import VBA_Parser, VBA_Scanner
from bs4 import BeautifulSoup
from pdfminer.converter import TextConverter
from pdfminer.layout import LAParams
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfparser import PDFParser
from io import StringIO
from zipfile import ZipFile


ACCESS_TOKEN = 'access_token'
CURRENT_TOKEN = None
LOG_DIRECTORY_NAME = 'logs'
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.000Z'

#Regex statements
url_re = re.compile(r'(http|ftp|https|ftps|scp):\/\/([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:\/~+#-;]*[\w@?^=%&\/~+#-])?')
domain_re = re.compile(r'\b((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\b')
ipv4_re = re.compile(r'((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
ipv6_re = re.compile(r'\b(?:[a-f0-9]{1,4}:|:){2,7}(?:[a-f0-9]{1,4}|:)\b')
pixeltrack_re = re.compile(r'<img src=[\"\']http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+[\"\'] (width|height)=[\"\']1[\"\'] (width|height)=[\"\']1[\"\']>')

#Setting minimum interval in TA to 60 seconds
def validate_input(helper, definition):
    interval_in_seconds = int(definition.parameters.get('interval'))
    if (interval_in_seconds < 60 or interval_in_seconds > 600):
        raise ValueError("field 'Interval' should be between 60 and 600")

#Obtain access token via oauth2
def _get_access_token(helper):
    
    if helper.get_arg('endpoint') == 'worldwide':
        login_url = 'https://login.microsoftonline.com/'
        graph_url = 'https://graph.microsoft.com/'
    elif helper.get_arg('endpoint') == 'gcchigh':
        login_url = 'https://login.microsoftonline.us/'
        graph_url = 'https://graph.microsoft.us/'
        
    global CURRENT_TOKEN
    if CURRENT_TOKEN is None:
        _data = {
            'client_id': helper.get_arg('global_account')['username'],
            'scope': graph_url + '.default',
            'client_secret': helper.get_arg('global_account')['password'],
            'grant_type': 'client_credentials',
            'Content-Type': 'application/x-www-form-urlencoded'
            }
        _url = login_url + helper.get_arg('tenant') + '/oauth2/v2.0/token'
        if (sys.version_info > (3, 0)):
            access_token = helper.send_http_request(_url, "POST", payload=urllib.parse.urlencode(_data), timeout=(15.0, 15.0)).json()
        else:
            access_token = helper.send_http_request(_url, "POST", payload=urllib.urlencode(_data), timeout=(15.0, 15.0)).json()

        CURRENT_TOKEN = access_token[ACCESS_TOKEN]
        return access_token[ACCESS_TOKEN]

    else:
        return CURRENT_TOKEN

#Returning version of TA
def _get_app_version(helper):
    app_version = ""
    if 'session_key' in helper.context_meta:
        session_key = helper.context_meta["session_key"]
        entity = splunk.entity.getEntity('/configs/conf-app','launcher', namespace=helper.get_app_name(), sessionKey=session_key, owner='nobody')
        app_version = entity.get('version')
    return app_version

#Function to write events to Splunk
def _write_events(helper, ew, messages=None):
    if messages:
        for message in messages:
            event = helper.new_event(
                source=helper.get_input_type(),
                index=helper.get_output_index(),
                sourcetype=helper.get_sourcetype(),
                data=json.dumps(message))
            ew.write_event(event)

#Purging of messages after ingest to Splunk.  This is using the recoverableitemspurges folder, which emulates a hard delete.
def _purge_messages(helper, messages):
    
    if helper.get_arg('endpoint') == 'worldwide':
        graph_url = 'https://graph.microsoft.com/v1.0'
    elif helper.get_arg('endpoint') == 'gcchigh':
        graph_url = 'https://graph.microsoft.us/v1.0'
        
    access_token = _get_access_token(helper)

    headers = {"Authorization": "Bearer " + access_token,
                "Content-type": "application/json"}

    #Turns off read receipts on messages in the compliance mailbox.  Doesn't affect read receipts to original user.
    _disable_rr = {
                 "singleValueExtendedProperties": [
                     {
                     "id": "Boolean 0x0C06",
                     "value": "false"
                     },
                     {
                     "id": "Boolean 0x0029",
                     "value": "false"
                     }
                 ]
                 }

    #Purge folder
    _data = {
            "destinationId": "recoverableitemspurges"
            }

    for message in messages:
        for item in message:

            if item["isReadReceiptRequested"]:
                remove_receipt_response = helper.send_http_request(graph_url + "/users/" + helper.get_arg('audit_email_account') + "/messages/" + item["id"], "PATCH", headers=headers, payload=_disable_rr, timeout=(15.0, 15.0))

            response = helper.send_http_request(graph_url + "/users/" + helper.get_arg('audit_email_account') + "/messages/" + item["id"] + "/move", "POST", headers=headers, payload=_data, timeout=(15.0, 15.0))

#Top level IOC extraction from various items (email bodies, supported file types, etc).  Currently only attempting URLS, domains, and IP address (v4 and v6). Calls URL, Domain, and IP address functions below.
def extract_iocs(helper, data):
    return itertools.chain(
        extract_urls(data),
        extract_domains(data),
        extract_ips(data)
    )

#URL IOC extraction function.
def extract_urls(data):
    urls = itertools.chain(
        url_re.finditer(data)
    )
    for url in urls:
        url = url.group(0)
        yield url

#Domain IOC extraction function.
def extract_domains(data):
    domains = itertools.chain(
        domain_re.finditer(data)
    )
    for domain in domains:
        domain = domain.group(0)
        yield domain

#Top level IP address IOC extraction function. Calls IPv4 and IPv6 functions below.
def extract_ips(data):
    return itertools.chain(
        extract_ipv4(data),
        extract_ipv6(data)
    )

#IPv4 IOC extraction function.
def extract_ipv4(data):
    ipv4s = itertools.chain(
        ipv4_re.finditer(data)
    )
    for ip in ipv4s:
        ip = ip.group(0)
        yield ip

#IPv6 IOC extraction function.
def extract_ipv6(data):
    ipv6s = itertools.chain(
        ipv6_re.finditer(data)
    )
    for ip in ipv6s:
        ip = ip.group(0)
        yield ip

#Function to check if returned url is secure
def is_https(url):
    if url.startswith("https://"):
        return True
    else:
        return False

#Main function for gathering emails.
def collect_events(helper, ew):
    
    if helper.get_arg('endpoint') == 'worldwide':
        graph_url = 'https://graph.microsoft.com/v1.0'
    elif helper.get_arg('endpoint') == 'gcchigh':
        graph_url = 'https://graph.microsoft.us/v1.0'
        
    access_token = _get_access_token(helper)

    headers = {"Authorization": "Bearer " + access_token,
                "User-Agent": "MicrosoftGraphEmail-Splunk/" + _get_app_version(helper)}
                #"Prefer": "outlook.body-content-type=text"}

    #defining email account to retrieve messages from
    endpoint = "/users/" + helper.get_arg('audit_email_account')

    #defining inbox id to retrieve messages from
    endpoint += "/mailFolders/inbox/messages/"

    #expanding property id 0x0E08 to gather message size, and then expanding attachments to get fileattachment type contentBytes
    endpoint += "?$expand=SingleValueExtendedProperties($filter=Id eq 'LONG 0x0E08'),attachments"
        
    #selecting which fields to retrieve from emails
    endpoint += "&$select=receivedDateTime,subject,sender,from,hasAttachments,internetMessageId,toRecipients,ccRecipients,bccRecipients,replyTo,internetMessageHeaders,body,bodyPreview,isReadReceiptRequested,isDeliveryReceiptRequested"

    #defining how many messages to retrieve from each page
    endpoint += "&$top=980"

    #getting the oldest messages first
    endpoint += "&$orderby=receivedDateTime"

    #getting the total count of messages in each round
    endpoint += "&$count=true"

    messages_response = helper.send_http_request(graph_url + endpoint, "GET", headers=headers, parameters=None, timeout=(15.0, 15.0)).json()

    helper.log_info("Retrieving " + str(messages_response['@odata.count']) + " messages")
    
    messages = []
    
    #Routine that iterates through the messages.  Uses the @odata.nextLink values to find the next endpoint to query.
    
    messages.append(messages_response['value'])

    #Calculate how many pages of 980 messages we'll attempt based on the interval value.  Helps to keep requests within API limits.
    
    interval_in_seconds = int(helper.get_arg('interval'))

    url_count_limit = (interval_in_seconds//60) - 1

    if url_count_limit>0:

        url_count = 0
    
        while ("@odata.nextLink" in messages_response) and (is_https(messages_response["@odata.nextLink"])):
            if url_count < url_count_limit:
                nextlinkurl = messages_response["@odata.nextLink"]
                messages_response = helper.send_http_request(nextlinkurl, "GET", headers=headers, parameters=None, timeout=(15.0, 15.0)).json()
                messages.append(messages_response['value'])
                url_count += 1
            else:
                helper.log_debug("Protecting API limits, breaking out")
                break

    #Routine to find attachments in messages.  This caters for both standard, as well as inline attachments.  MS Graph doesn't list inline attachments in the "hasAttachments" value, this fixes that.
    message_data = []
    attach_data = []
    
    for message in messages:
        
        for item in message:

            message_items = {}
            
            message_items['_time'] = item['receivedDateTime']
            message_items['to'] = item['toRecipients']
            message_items['from'] = item['from']
            message_items['sender'] = item['sender']
            message_items['subject'] = item['subject']
            message_items['id'] = item['id']
            message_items['internetMessageId'] = item['internetMessageId']
            message_items['ccRecipients'] = item['ccRecipients']
            message_items['bccRecipients'] = item['bccRecipients']
            message_items['replyTo'] = item['replyTo']
            message_items['hasAttachments'] = item['hasAttachments']
            
            message_body = item['body']['content']
            body_preview = item['bodyPreview']
            attachments = item['attachments']
            single_value_properties = item['singleValueExtendedProperties']

            if 'internetMessageHeaders' in item:
                internet_message_headers = item['internetMessageHeaders']

                if helper.get_arg('get_internet_headers'):
                    message_items['Internet-Headers'] = internet_message_headers

                #message path calculations
                message_path = []
                path_item = {}
            
                for item in internet_message_headers:
                    if item['name'] == "Received":
                        path_item=item
                        message_path.append(path_item)
            
                src_line = str(message_path[-1])
                dest_line = str(message_path[0])
            
                re_by = re.compile(r'(?<=\bby\s)(\S+)')
                re_from = re.compile(r'(?<=\bfrom\s)(\S+)')
            
                dest = re_by.search(dest_line)
            
                if re_from.search(src_line):
                    src = re_from.search(src_line)
                elif re_by.search(src_line):
                    src = re_by.search(src_line)

                message_items['src'] = str(src[0])    
                message_items['dest'] = str(dest[0])

                if helper.get_arg('get_message_path'):
                    message_items['message_path'] = message_path

                if helper.get_arg('get_x_headers'):
                
                    x_headers = []
                    x_header_item = {}
                
                    for item in internet_message_headers:
                        if "X-" in item['name']:
                            x_header_item=item
                            x_headers.append(x_header_item)
                        
                    message_items['X-Headers'] = x_headers

                if helper.get_arg('get_auth_results'):
                
                    auth_results = []
                    auth_results_item = {}
                
                    for item in internet_message_headers:
                        if "Authentication-Results" in item['name']:
                            auth_results_item=item
                            auth_results.append(auth_results_item)
                        
                    message_items['Authentication-Results'] = auth_results

                if helper.get_arg('get_spf_results'):
                
                    spf_results = []
                    spf_results_item = {}
                
                    for item in internet_message_headers:
                        if "Received-SPF" in item['name']:
                            spf_results_item=item
                            spf_results.append(spf_results_item)
                        
                    message_items['Received-SPF'] = spf_results

                if helper.get_arg('get_dkim_signature'):
                
                    dkim_sig = []
                    dkim_sig_item = {}
                
                    for item in internet_message_headers:
                        if "DKIM-Signature" in item['name']:
                            dkim_sig_item=item
                            dkim_sig.append(dkim_sig_item)
                        
                    message_items['DKIM-Signature'] = dkim_sig

            #tracking pixel detection
            if pixeltrack_re.search(message_body):
                pixel_data = pixeltrack_re.search(message_body)
                message_items['tracking_pixel'] = "true"
                message_items['tracking_pixel_data'] = pixel_data.group(0)
            else:
                message_items['tracking_pixel'] = "false"

            #size mapping
            for item in single_value_properties:
                if item['id'] == "Long 0xe08":
                    message_items['size'] = item['value']
                    
            if helper.get_arg('get_body'):
                message_items['body'] = message_body
            
            if helper.get_arg('get_body_preview'):
                message_items['bodyPreview'] = body_preview
            
            if helper.get_arg('get_internet_headers'):
                message_items['Internet-Headers'] = internet_message_headers
            
            if helper.get_arg('get_attachment_info'):
                message_items['attachments'] = attachments
                
            if helper.get_arg('get_body'):
                if helper.get_arg('extract_iocs'):

                    iocs = extract_iocs(helper, message_items["body"])

                    email_iocs = []

                    for ioc in iocs:
                        if not ioc in email_iocs:
                            email_iocs.append(ioc)
                    if email_iocs:
                        message_items['iocs'] = email_iocs
                        
            if helper.get_arg('get_attachment_info'):

                if message_items['attachments'] is not None:


                    for attachment in message_items["attachments"]:

                        #Looks for itemAttachment type, which is a contact, event, or message that's attached.
                        if attachment["@odata.type"] == "#microsoft.graph.itemAttachment":

                            my_added_data = {}
                            
                            my_added_data['name'] = attachment['name']
                            my_added_data['odata_type'] = attachment['@odata.type']
                            my_added_data['id'] = attachment['id']
                            my_added_data['contentType'] = attachment['contentType']
                            my_added_data['size'] = attachment['size']

                            attach_data.append(my_added_data)
                        
                        #Looks for referenceAttachment type, which is a link to a file on OneDrive or other supported storage location
                        if attachment["@odata.type"] == "#microsoft.graph.referenceAttachment":

                            my_added_data = {}

                            my_added_data['name'] = attachment['name']
                            my_added_data['odata_type'] = attachment['@odata.type']
                            my_added_data['id'] = attachment['id']
                            my_added_data['contentType'] = attachment['contentType']
                            my_added_data['size'] = attachment['size']

                            attach_data.append(my_added_data)
                        
                        #Looks for fileAttachment type, which is a standard email attachment.
                        if attachment["@odata.type"] == "#microsoft.graph.fileAttachment":

                            my_added_data = {}

                            attach_b64decode = base64.b64decode(attachment['contentBytes'])

                            #Selects which hashing algorithm (md5, sha1, sha256) to use on the attachment.
                            if helper.get_arg('get_attachment_info') and helper.get_arg('file_hash_algorithm') == 'md5':
                                hash_object = hashlib.md5(attach_b64decode)
                            if helper.get_arg('get_attachment_info') and helper.get_arg('file_hash_algorithm') == 'sha1':
                                hash_object = hashlib.sha1(attach_b64decode)
                            if helper.get_arg('get_attachment_info') and helper.get_arg('file_hash_algorithm') == 'sha256':
                                hash_object = hashlib.sha256(attach_b64decode)

                            att_hash = hash_object.hexdigest()

                            my_added_data['name'] = attachment['name']
                            my_added_data['odata_type'] = attachment['@odata.type']
                            my_added_data['id'] = attachment['id']
                            my_added_data['contentType'] = attachment['contentType']
                            my_added_data['size'] = attachment['size']
                            my_added_data['file_hash'] = att_hash
                        
                            #Attempts to open up zip file to list file names and hashes if the option is selected in the input.
                            if helper.get_arg('get_attachment_info') and helper.get_arg('read_zip_files') and attachment['@odata.mediaContentType'] == 'application/zip':

                                filedata_encoded = attachment['contentBytes'].encode()
                                file_bytes = base64.b64decode(filedata_encoded)

                                zipbytes = io.BytesIO(file_bytes)
                            
                                try:
                                    zipfile = ZipFile(zipbytes)
                                
                                    zipmembers = zipfile.namelist()
                                
                                    zip_files = []
                                    zip_hashes = []
                                
                                    for file in zipmembers:
                                   
                                        zip_read = zipfile.read(file)
                                    
                                        if helper.get_arg('file_hash_algorithm') == 'md5':
                                            hash_object = hashlib.md5(zip_read)
                                        if helper.get_arg('file_hash_algorithm') == 'sha1':
                                            hash_object = hashlib.sha1(zip_read)
                                        if helper.get_arg('file_hash_algorithm') == 'sha256':
                                            hash_object = hashlib.sha256(zip_read)    
                                        
                                        zip_hash = hash_object.hexdigest()
                                    
                                        if not file in zip_files:
                                        
                                            zip_files.append(file)
                                            zip_hashes.append(zip_hash)

                                        if zip_files:
                                            my_added_data['zip_files'] = zip_files
                                            my_added_data['zip_hashes'] = zip_hashes
                                        
                                except:
                                    my_added_data['attention'] = 'could not extract the zip file, may be encrypted'
                                
                                
                            #Routine to gather info on CSV file types.
                            if helper.get_arg('get_attachment_info') and attachment['@odata.mediaContentType'] == 'text/csv':

                                filedata_encoded = attachment['contentBytes'].encode()
                                file_bytes = base64.b64decode(filedata_encoded)

                                csvbytes = io.BytesIO(file_bytes)
                            
                                try:
                                    csvstring = csvbytes.read().decode('utf-8')

                                    if helper.get_arg('extract_iocs'):

                                        iocs = extract_iocs(helper, csvstring)

                                        csv_iocs = []

                                        for ioc in iocs:
                                            if not ioc in csv_iocs:
                                                csv_iocs.append(ioc)
                                        if csv_iocs:
                                            my_added_data['iocs'] = csv_iocs

                                    #Will attempt to ingest the actual contents of the CSV file if this option is selected in the input.
                                    if 'csv' in helper.get_arg('attachment_data_ingest'):
                                        my_added_data['csv_data'] = csvstring
                                    
                                except:
                                    my_added_data['attention'] = 'could not parse the csv document, may be encrypted'
                                

                            #Routine to gather info on HTML file types.
                            if helper.get_arg('get_attachment_info') and attachment['@odata.mediaContentType'] == 'text/html':

                                filedata_encoded = attachment['contentBytes'].encode()
                                file_bytes = base64.b64decode(filedata_encoded)

                                try:
                                    uncooked_soup = html.unescape(str(file_bytes))

                                    soup = BeautifulSoup(uncooked_soup)

                                    soup_data = str(soup)

                                    if helper.get_arg('extract_iocs'):

                                        iocs = extract_iocs(helper, soup_data)

                                        html_iocs = []

                                        for ioc in iocs:
                                            if not ioc in html_iocs:
                                                html_iocs.append(ioc)
                                        if html_iocs:
                                            my_added_data['iocs'] = html_iocs

                                    #Will attempt to ingest the actual contents of the HTML file if this option is selected in the input.
                                    if 'html' in helper.get_arg('attachment_data_ingest'):
                                        my_added_data['html_data'] = soup_data
                                    
                                except:
                                    my_added_data['attention'] = 'could not parse the html document, may be encrypted'


                            #Routine to gather info on PDF file types.
                            if helper.get_arg('get_attachment_info') and attachment['@odata.mediaContentType'] == 'application/pdf':

                                filedata_encoded = attachment['contentBytes'].encode()

                                file_bytes = base64.b64decode(filedata_encoded)

                                pdf_content = io.BytesIO(file_bytes)

                                output_string = StringIO()

                                try:
                                    parser = PDFParser(pdf_content)
                                
                                    doc = PDFDocument(parser)

                                    rsrcmgr = PDFResourceManager()

                                    device = TextConverter(rsrcmgr, output_string, laparams=LAParams())

                                    interpreter = PDFPageInterpreter(rsrcmgr, device)

                                    for page in PDFPage.create_pages(doc):
                                        interpreter.process_page(page)

                                    pdf_text = output_string.getvalue()
                                
                                    if helper.get_arg('extract_iocs'):

                                        iocs = extract_iocs(helper, pdf_text)

                                        pdf_iocs = []

                                        for ioc in iocs:
                                            if not ioc in pdf_iocs:
                                                pdf_iocs.append(ioc)
                                            if pdf_iocs:
                                                my_added_data['iocs'] = pdf_iocs

                                    #Will attempt to ingest the actual contents of the PDF file if this option is selected in the input.
                                    if 'pdf' in helper.get_arg('attachment_data_ingest'):
                                        my_added_data['pdf_data'] = pdf_text
                                
                                except:
                                    my_added_data['attention'] = 'could not parse the pdf document, may be encrypted'


                            #Routine to gather info on XML file types.
                            if helper.get_arg('get_attachment_info') and attachment['@odata.mediaContentType'] == 'text/xml':

                                filedata_encoded = attachment['contentBytes'].encode()

                                file_bytes = base64.b64decode(filedata_encoded)

                                try:
                                    soup = BeautifulSoup(file_bytes, 'lxml')

                                    soup_data = str(soup)

                                    if helper.get_arg('extract_iocs'):

                                        iocs = extract_iocs(helper, soup_data)

                                        xml_iocs = []

                                        for ioc in iocs:
                                            if not ioc in xml_iocs:
                                                xml_iocs.append(ioc)
                                        if xml_iocs:
                                            my_added_data['iocs'] = xml_iocs

                                    #Will attempt to ingest the actual contents of the XML file if this option is selected in the input.
                                    if 'xml' in helper.get_arg('attachment_data_ingest'):
                                        my_added_data['xml_data'] = soup_data
                                    
                                except:
                                    my_added_data['attention'] = 'could not parse the xml document, may be encrypted'
                                

                            #Routine to do macro analysis on files of supported content types listed below if selected in the input setup.  This uses OLEVBA tools to detect macros in the attachment, then analyses the macros.
                            if helper.get_arg('get_attachment_info') and helper.get_arg('macro_analysis'):

                                filename = attachment['name']

                                #Content types supported by OLEVBA.
                                supported_content = ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                                'application/vnd.openxmlformats-officedocument.spreadsheetml.template',
                                'application/vnd.ms-excel.sheet.macroenabled.12',
                                'application/vnd.ms-excel.template.macroenabled.12',
                                'application/vnd.ms-excel.addin.macroenabled.12',
                                'application/vnd.ms-excel.sheet.binary.macroenabled.12',
                                'application/vnd.ms-excel',
                                'application/xml',
                                'application/vnd.ms-powerpoint',
                                'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                                'application/vnd.openxmlformats-officedocument.presentationml.template',
                                'application/vnd.openxmlformats-officedocument.presentationml.slideshow',
                                'application/vnd.ms-powerpoint.addin.macroenabled.12',
                                'application/vnd.ms-powerpoint.presentation.macroenabled.12',
                                'application/vnd.ms-powerpoint.template.macroenabled.12',
                                'application/vnd.ms-powerpoint.slideshow.macroenabled.12',
                                'application/msword',
                                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                                'application/vnd.openxmlformats-officedocument.wordprocessingml.template',
                                'application/vnd.ms-word.document.macroenabled.12',
                                'application/vnd.ms-word.template.macroenabled.12']

                                if attachment['@odata.mediaContentType'] in supported_content:

                                    filedata_encoded = attachment['contentBytes'].encode()
                                    file_bytes = base64.b64decode(filedata_encoded)

                                    try:
                                        vbaparser = VBA_Parser(filename, data=file_bytes)

                                        if vbaparser.detect_vba_macros():
                                            my_added_data['macros_exist'] = "true"

                                            macro_analysis = VBA_Parser.analyze_macros(vbaparser)
                                            helper.log_debug("GET Response: " + json.dumps(macro_analysis, indent=4))

                                            if macro_analysis == []:
                                                my_added_data['macro_analysis'] = "Macro doesn't look bad, but I never trust macros."
                                            else:
                                                my_added_data['macros_analysis'] = macro_analysis

                                        else:
                                            my_added_data['macros_exist'] = "false"
                                        
                                    except:
                                        my_added_data['attention'] = 'could not extract the office document, may be encrypted'

                            attach_data.append(my_added_data)

            message_items['attachments'] = attach_data
            message_data.append(message_items)
        
        _write_events(helper, ew, messages=message_data)
    _purge_messages(helper, messages)
