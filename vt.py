import requests
import sys

class VT:

    keys = ['<VT Key>', 
            '<VT Key>',
            '<VT Key>',
            '<VT Key>',
            '<VT Key>',
            '<VT Key>',
            '<VT Key>',
            '<VT Key>', 
            '<VT Key>',
            '<VT Key>',
            '<VT Key>',
            '<VT Key>',
            '<VT Key>',
            '<VT Key>',
            '<VT Key>',
            '<VT Key>',
            '<VT Key>',
            '<VT Key>',
            '<VT Key>',
            '<VT Key>',
            '<VT Key>',
            '<VT Key>',
            '<VT Key>']

    #academic_key = '<VT Key>' # Omar's Academic API key
    academic_key = '<VT Key>' # Eric's Academic API key
    key_flag = 0
    upload_count = 0

    def __init__(self):
        self.upload_files = []
        self.ufpath = ''
        self.api_key = ''
        self.api_url = 'https://www.virustotal.com/vtapi/v2/'
        self.proxies = None
        self.num_204 = 0

    def scan_url(self, this_url, timeout=None):
        params = {'apikey': self.api_key, 'url': this_url}
        try:
            response = requests.post(self.api_url + 'url/scan', params=params, proxies=self.proxies, timeout=timeout)
        except requests.RequestException as e:
            return dict(error=str(e))

        scan =  _return_response_and_status_code(response)
        if ('error' not in scan): #and ('results' in scan):
            if scan['results']['response_code'] == 1:
                return "PASS"               
            else:
                #return "FAIL"
                return scan
        elif scan['response_code'] == 204:
            self.num_204 += 1
            if (self.num_204 == len(self.keys)):
                #return "FAIL"
                return scan
            self.key_flag = (self.key_flag + 1) % len(self.keys)
            self.setkey(self.keys[self.key_flag])
            print("Current Key:", self.keys[self.key_flag])
            return self.scan_url(this_url)
        else:
            return scan
            #return "FAIL"

    def get_url_report(self, this_url, scan='0', timeout=None):
        """ Get the scan results for a URL. (can do batch searches like get_file_report)
        :param this_url: a URL will retrieve the most recent report on the given URL. You may also specify a scan_id
                         (sha256-timestamp as returned by the URL submission API) to access a specific report. At the
                         same time, you can specify a CSV list made up of a combination of hashes and scan_ids so as
                         to perform a batch request with one single call (up to 4 resources per call with the standard
                         request rate). When sending multiples, the scan_ids or URLs must be separated by a new line
                         character.
        :param scan: (optional): this is an optional parameter that when set to "1" will automatically submit the URL
                      for analysis if no report is found for it in VirusTotal's database. In this case the result will
                      contain a scan_id field that can be used to query the analysis report later on.
        :param timeout: The amount of time in seconds the request should wait before timing out.
        :return: JSON response
        """
        params = {'apikey': self.api_key, 'resource': this_url, 'scan': scan}

        try:
            response = requests.get(self.api_url + 'url/report', params=params, proxies=self.proxies, timeout=timeout)
        except requests.RequestException as e:
            return dict(error=str(e))

        rep =  _return_response_and_status_code(response)
        if ('error' not in rep): 
            if rep['results']['response_code'] == 1:
                return rep               
            else:
                #return "FAIL"
                return dict(error=rep)
        elif scan['response_code'] == 204:
            self.num_204 += 1
            if (self.num_204 == len(self.keys)):
                #return "FAIL"
                return dict(error="204 on all API keys")
            self.key_flag = (self.key_flag + 1) % len(self.keys)
            self.setkey(self.keys[self.key_flag])
            return self.get_url_report(this_url)
        else:
            return "FAIL"

    # set the file path containing all urls to be examined
    def setufpath(self, ufpath):
        self.ufpath = ufpath

    # set a new api-key
    def setkey(self, key):
        self.api_key = key

    # set an output file path
    def setofile(self, ofile):
        self.ofile = ofile

    # set an output file path only contains malicious results
    def setomfile(self, omfile):
        self.omfile = omfile

def run_VT_scan(link):
    vt = VT()
    vt.setkey(vt.keys[vt.key_flag])
    vt.num_204 = 0

    vt.upload_files.append(link)

    avlist = []
    for url in vt.upload_files:
        #print("Scanning URL")
        vt.num_204 = 0
        scan = vt.scan_url(url)
        #print("Returned SCAN", scan)
        if scan == "PASS":
            vt.num_204 = 0
            getr = vt.get_url_report(url)
            if getr != "FAIL":    
                if ('error' not in getr) and ('results' in getr):
                    if getr['results']['positives'] > 0:
                        for av in getr['results']['scans']:
                            if getr['results']['scans'][av]['detected']:
                                avlist.append('+ ' + av + ':  ' + getr['results']['scans'][av]['result'])
                #print(avlist)
                return avlist
            else:
                return "GET_REPORT_FAIL" 
        else:
            #return "SCAN_FAIL"
            return scan 


def _return_response_and_status_code(response, json_results=True):
    """ Output the requests response content or content as json and status code
    :rtype : dict
    :param response: requests response object
    :param json_results: Should return JSON or raw content
    :return: dict containing the response content and/or the status code with error string.
    """
    if response.status_code == requests.codes.ok:
        return dict(results=response.json() if json_results else response.content, response_code=response.status_code)
    elif response.status_code == 400:
        return dict(
            error='package sent is either malformed or not within the past 24 hours.',
            response_code=response.status_code)
    elif response.status_code == 204:
        return dict(
            error='You exceeded the public API request rate limit (4 requests of any nature per minute)',
            response_code=response.status_code)
    elif response.status_code == 403:
        return dict(
            error='You tried to perform calls to functions for which you require a Private API key.',
            response_code=response.status_code)
    elif response.status_code == 404:
        return dict(error='File not found.', response_code=response.status_code)
    else:
        return dict(response_code=response.status_code)

if __name__ == "__main__":
    run_VT_scan(sys.argv[1])    
