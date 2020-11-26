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
from email.parser import HeaderParser
from email.parser import BytesParser
from oletools.olevba import VBA_Parser, VBA_Scanner
from bs4 import BeautifulSoup

ACCESS_TOKEN = 'access_token'
CURRENT_TOKEN = None
LOG_DIRECTORY_NAME = 'logs'
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.000Z'


def validate_input(helper, definition):
    interval_in_seconds = int(definition.parameters.get('interval'))
    if interval_in_seconds < 60:
        raise ValueError("field 'Interval' should be at least 60")
    filter_arg = definition.parameters.get('filter')
    if filter_arg is not None and 'lastModifiedDateTime' in filter_arg:
        raise ValueError("'lastModifiedDateTime' is a reserved property and cannot be part of the filter")


def _get_access_token(helper):
    global CURRENT_TOKEN
    if CURRENT_TOKEN is None:
        _data = {
            'client_id': helper.get_arg('global_account')['username'],
            'scope': 'https://graph.microsoft.com/.default',
            'client_secret': helper.get_arg('global_account')['password'],
            'grant_type': 'client_credentials',
            'Content-Type': 'application/x-www-form-urlencoded'
            }
        _url = 'https://login.microsoftonline.com/' + helper.get_arg('tenant') + '/oauth2/v2.0/token'
        if (sys.version_info > (3, 0)):
            access_token = helper.send_http_request(_url, "POST", payload=urllib.parse.urlencode(_data), timeout=(15.0, 15.0)).json()
        else:
            access_token = helper.send_http_request(_url, "POST", payload=urllib.urlencode(_data), timeout=(15.0, 15.0)).json()

        CURRENT_TOKEN = access_token[ACCESS_TOKEN]
        return access_token[ACCESS_TOKEN]

    else:
        return CURRENT_TOKEN

def _get_app_version(helper):
    app_version = ""
    if 'session_key' in helper.context_meta:
        session_key = helper.context_meta["session_key"]
        entity = splunk.entity.getEntity('/configs/conf-app','launcher', namespace=helper.get_app_name(), sessionKey=session_key, owner='nobody')
        app_version = entity.get('version')
    return app_version


def _write_events(helper, ew, emails=None):
    if emails:
        for email in emails:
            event = helper.new_event(
                source=helper.get_input_type(),
                index=helper.get_output_index(),
                sourcetype=helper.get_sourcetype(),
                data=json.dumps(email))
            ew.write_event(event)

def _get_inbox_id(helper):
    access_token = _get_access_token(helper)
    headers = {"Authorization": "Bearer " + access_token,
                "User-Agent": "MicrosoftGraphEmail-Splunk/" + _get_app_version(helper)}

    response = helper.send_http_request("https://graph.microsoft.com/v1.0/users/" + helper.get_arg('audit_email_account') + "/mailFolders", "GET", headers=headers, parameters=None, timeout=(15.0, 15.0)).json()

    for item in response["value"]:
        if item["displayName"] == "Inbox":
            inbox_id = str(item["id"])

    return inbox_id

def _purge_messages(helper, messages):
    access_token = _get_access_token(helper)
    inbox_id = _get_inbox_id(helper)

    headers = {"Authorization": "Bearer " + access_token,
                "Content-type": "application/json"}
    _data = {
            "destinationId": "recoverableitemspurges"
            }

    for message in messages:
        for item in message:
            response = helper.send_http_request("https://graph.microsoft.com/v1.0/users/" + helper.get_arg('audit_email_account') + "/messages/" + item["id"] + "/move", "POST", headers=headers, payload=_data, timeout
=(15.0, 15.0))

def collect_events(helper, ew):
    access_token = _get_access_token(helper)
    inbox_id = _get_inbox_id(helper)
    headers = {"Authorization": "Bearer " + access_token,
                "User-Agent": "MicrosoftGraphEmail-Splunk/" + _get_app_version(helper)}

    interval_in_seconds = int(helper.get_arg('interval'))

    endpoint = "/users/" + helper.get_arg('audit_email_account')
    endpoint += "/mailFolders/" + inbox_id + "/messages/?$expand=SingleValueExtendedProperties($filter=Id eq 'LONG 0x0E08')"
    endpoint += "&$select=subject,sender,hasAttachments,internetMessageId,toRecipients,ccRecipients,bccRecipients,replyTo"

    if helper.get_arg('get_body_preview'):
            endpoint += ",bodyPreview"

    messages_response = helper.send_http_request("https://graph.microsoft.com/v1.0" + endpoint, "GET", headers=headers, parameters=None, timeout=(15.0, 15.0)).json()

    messages = []

    messages.append(messages_response['value'])
    url_count = 1
    while "@odata.nextLink" in messages_response:
        if url_count < 1000:
              nextlinkurl = messages_response["@odata.nextLink"]
              messages_response = helper.send_http_request(nextlinkurl, "GET", headers=headers, parameters=None, timeout=(15.0, 15.0)).json()
              messages.append(messages_response['value'])
              url_count += 1
        else:
            helper.log_debug("Loop detecting, breaking out")
            break

    for message in messages:
        for item in message:

            endpoint = "/users/" + helper.get_arg('audit_email_account')
            endpoint += "/messages/" + item["id"]
            endpoint += "/attachments"

            attach_exist = helper.send_http_request("https://graph.microsoft.com/v1.0" + endpoint, "GET", headers=headers, parameters=None, timeout=(15.0, 15.0)).json()

            if helper.get_arg('get_attachment_info') and (attach_exist['value'] is not None):

                for attachment in attach_exist["value"]:
                    if attachment["@odata.type"] == "#microsoft.graph.fileAttachment":

                        endpoint = "/users/" + helper.get_arg('audit_email_account')
                        endpoint += "/messages/" + item["id"]
                        endpoint += "/attachments/?$select=id,size,contentType,name&$expand=microsoft.graph.itemattachment/item/"

                        attach_resp = helper.send_http_request("https://graph.microsoft.com/v1.0" + endpoint, "GET", headers=headers, parameters=None, timeout=(15.0, 15.0)).json()

                        attach_data = []
                        count = 0

                        for attachment in attach_resp["value"]:

                            attach_endpoint = "/users/" + helper.get_arg('audit_email_account')
                            attach_endpoint += "/messages/" + item["id"]
                            attach_endpoint += "/attachments/" + attachment["id"]

                            response = helper.send_http_request("https://graph.microsoft.com/v1.0" + attach_endpoint, "GET", headers=headers, parameters=None, timeout=(15.0, 15.0)).json()
                            
                            # helper.log_debug(response['contentBytes'])
                            
                            attach_b64decode = base64.b64decode(response['contentBytes'])
                            
                            if helper.get_arg('get_attachment_info') and helper.get_arg('file_hash_algorithm') == 'md5':
                                hash_object = hashlib.md5(attach_b64decode)
                            if helper.get_arg('get_attachment_info') and helper.get_arg('file_hash_algorithm') == 'sha1':
                                hash_object = hashlib.sha1(attach_b64decode)
                            if helper.get_arg('get_attachment_info') and helper.get_arg('file_hash_algorithm') == 'sha256':
                                hash_object = hashlib.sha256(attach_b64decode)

                            att_hash = hash_object.hexdigest()

                            my_added_data = attach_resp['value']
                            my_added_data[count]['file_hash'] = att_hash
                            
                            if helper.get_arg('get_attachment_info') and ('html_analysis' in helper.get_arg('attachment_analysis')):
                                
                                supported_content = ['text/html']
                                
                                if response['@odata.mediaContentType'] in supported_content:
                                    
                                    filedata_encoded = response['contentBytes'].encode()
                                    file_bytes = base64.b64decode(filedata_encoded)
                                    
                                    uncooked_soup = html.unescape(str(file_bytes))
                                    
                                    soup = BeautifulSoup(uncooked_soup)
                                    
                                    soup_data = str(soup)
                                    
                                    my_added_data[count]['html_data'] = soup_data
                                    
                                    links = re.findall(r'(http|ftp|https):\/\/([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:\/~+#-;]*[\w@?^=%&\/~+#-])?', soup_data)
                                    
                                    html_links = []

                                    for link in links:
                                        link_url = link[0] + "://" + link[1] + link[2]
                                        if not link_url in html_links:
                                            html_links.append(link_url)

                                    if html_links:
                                        my_added_data[count]['links'] = html_links
                                        
                                
                            if helper.get_arg('get_attachment_info') and ('macro_analysis' in helper.get_arg('attachment_analysis')):
                            
                                filename = response['name']

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

                                if response['@odata.mediaContentType'] in supported_content:

                                    filedata_encoded = response['contentBytes'].encode()
                                    file_bytes = base64.b64decode(filedata_encoded)

                                    vbaparser = VBA_Parser(filename, data=file_bytes)

                                    if vbaparser.detect_vba_macros():
                                        my_added_data[count]['macros_exist'] = "true"

                                        macro_analysis = VBA_Parser.analyze_macros(vbaparser)
                                        helper.log_debug("GET Response: " + json.dumps(macro_analysis, indent=4))

                                        if macro_analysis == []:
                                            my_added_data[count]['macro_analysis'] = "Macro doesn't look bad, but I never trust macros."
                                        else:
                                            my_added_data[count]['macros_analysis'] = macro_analysis

                                    else:
                                        my_added_data[count]['macros_exist'] = "false"

                            count += 1

                        attach_data.append(my_added_data)

                        item['attachments'] = attach_data

    for message in messages:
        for item in message:

            endpoint = "/users/" + helper.get_arg('audit_email_account')
            endpoint += "/messages/" + item["id"]

            body_extract = helper.send_http_request("https://graph.microsoft.com/v1.0" + endpoint, "GET", headers=headers, parameters=None, timeout=(15.0, 15.0)).json()

            body_payload = body_extract["body"]["content"]

            if helper.get_arg('get_body'):
                soup = BeautifulSoup(body_payload, 'lxml')
                soup_data = str(soup.text)
                item['body'] = soup_data
                
            links = re.findall(r'(http|ftp|https):\/\/([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:\/~+#-;]*[\w@?^=%&\/~+#-])?', body_payload)

            email_links = []

            for link in links:
                link_url = link[0] + "://" + link[1] + link[2]
                if not link_url in email_links:
                    email_links.append(link_url)

            if email_links:
                item['links'] = email_links

    
    for message in messages:
        if helper.get_arg('show_relays'):
            for item in message:

                endpoint = "/users/" + helper.get_arg('audit_email_account')
                endpoint += "/messages/" + item["id"] + "/$value"

                mime_response = helper.send_http_request("https://graph.microsoft.com/v1.0" + endpoint, "GET", headers=headers, parameters=None, timeout=(15.0, 15.0)).content

                email = BytesParser().parsebytes(mime_response)
            
                relays = email.get_all('Received')

                item['relays'] = relays

        _write_events(helper, ew, emails=message)
    _purge_messages(helper, messages)
