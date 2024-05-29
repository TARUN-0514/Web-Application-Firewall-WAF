import xml.etree.ElementTree as ET
import urllib.parse
import base64
import csv

log_path = 'all2.log'
output_csv_log = 'all2.csv'
class_flag = "bad"

class LogParse:
    def __init__(self):
        pass

    def parse_log(self, log_path):
        result = {}
        try:
            with open(log_path):
                pass
        except IOError:
            print("[+] Error!!!", log_path, "doesn't exist...")
            exit()
        try:
            tree = ET.parse(log_path)
        except Exception as e:
            print('[+] Oops..! Please make sure binary data is not present in Log, like raw image dump')
            exit()
        root = tree.getroot()
        for reqs in root.findall('item'):
            raw_req = reqs.find('request').text
            raw_req = urllib.parse.unquote(raw_req)
            raw_resp = reqs.find('response').text
            result[raw_req] = raw_resp
        return result

    def parseRawHTTPReq(self, rawreq):
        headers = {}
        method = None
        body = None
        path = None
        raw = ""

        try:
            raw = rawreq.decode('utf-8', errors='replace')
        except Exception as e:
            raw = rawreq

        sp = raw.split('\r\n\r\n', 1)
        if sp[1] != "":
            head = sp[0]
            body = sp[1]
        else:
            head = sp[0]
            body = ""
        c1 = head.split('\n', head.count('\n'))
        method = c1[0].split(' ', 2)[0]
        path = c1[0].split(' ', 2)[1]

        for i in range(1, len(c1)):
            slice1 = c1[i].split(': ', 1)
            if slice1[0] != "":
                try:
                    headers[slice1[0]] = slice1[1]
                except:
                    pass

        return headers, method, body, path

badwords = ['sleep', 'drop', 'uid', 'select', 'waitfor', 'delay', 'system', 'union', 'order by', 'group by']

def extract_features(raw_req):
    features = {}

    # Check for the presence of bad keywords
    for keyword in badwords:
        if keyword in raw_req:
            features[keyword] = 1
        else:
            features[keyword] = 0

    # Check for the presence of bad characters
    for char in bad_characters:
        if char in raw_req:
            features[char] = 1
        else:
            features[char] = 0

    return features

# Define a list of bad characters (add it if needed)
bad_characters = ["'", '"', "--", "{", "}", " "]

f = open(output_csv_log, "w")
c = csv.writer(f)
c.writerow(["method", "path", "body", "single_q", "double_q", "spaces", "braces", "badwords", "class"])  # Include headers for features
f.close()

lp = LogParse()
result = lp.parse_log(log_path)
f = open(output_csv_log, "a")  # Use 'a' to append to the CSV file
c = csv.writer(f)
for items in result:
    raaw = base64.b64decode(items).decode('utf-8', errors='replace')  # Decode to string
    headers, method, body, path = lp.parseRawHTTPReq(raaw)

    # Extracting features
    features = extract_features(raaw)

    # Adding feature values to the row data
    # Calculate the values for 'single_q', 'double_q', 'spaces', and 'braces'
    single_q = raaw.count("'")
    double_q = raaw.count('"')
    spaces = raaw.count(' ')
    braces = raaw.count('{') + raaw.count('}')

    # Determine the 'class' value
    if class_flag in raaw:
        class_value = "bad"
    else:
        class_value = "good"

    row_data = [method, path, body, single_q, double_q, spaces, braces, sum(features.values()), class_value]

    # Writing CSV row
    c.writerow(row_data)

f.close()
