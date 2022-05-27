'''
MIT License

show_me_them_cookies

Copyright (c) 2022 Control-F Ltd

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

# show_me_them_cookies
# Tested on iOS 14.x-15.x.
# Usage: 'python show_me_them_cookies.py Cookies.binarycookies'

__version__ = 0.02
__description__ = 'Control-F - Apple Binary Cookie Parser'
__contact__ = 'mike.bangham@controlf.co.uk'

import sys
from struct import unpack
from collections import namedtuple
from datetime import datetime
import pandas as pd

# Apple cocoa timestamp epoch
cocoa_delta = 978307200


def pandafy(cookie_dict):
    # build a dataframe that can be ingested into the timeline tool Replay
    # 'Start', 'End', 'Start_HR', 'End_HR', 'timelapse', 'str_value', 'value' are ordered constants
    columns = ['Start', 'End', 'Start_HR', 'End_HR', 'timelapse', 'str_value', 'value',
               'Path', 'URL', 'Expires', 'Flag']
    rows = []
    pages = cookie_dict['header']['page_count']
    for page in range(pages):
        for cookie in cookie_dict['header']['pages'][page]['cookies']:
            cd = cookie_dict['header']['pages'][page]['cookies'][cookie]['data']
            rows.append([int(cd['last_access_epoch']), int(cd['last_access_epoch']),
                         cd['Last Access'], cd['Last Access'], 0,
                         cd['Name'], cd['Value'], cd['Path'], cd['URL'], cd['Expires'], cd['flag']])
    return pd.DataFrame(rows, columns=columns)


def unpacker(struct_arg, data, fields=None):
    # Accepts a struct argument, the packed binary data and optional fields.
    if fields:
        # returns a dictionary where the field is the key and the unpacked data is value.
        attr1 = namedtuple('struct', fields)
        return attr1._asdict(attr1._make(unpack(struct_arg, data)))
    else:
        # or just return value of single argument
        return unpack(struct_arg, data)[0]


class CookieParser:
    def __init__(self, input_file):
        self.binary_file = open(input_file, "rb")
        self.cookie_dict = dict()

    def process(self):
        # Extract 1 x 4 byte char[] 'magic' and 1 x 4 byte int
        self.cookie_dict['header'] = unpacker('>4s i', self.binary_file.read(8), ['magic', 'page_count'])
        if self.cookie_dict['header']['magic'] == b'cook':
            if self.cookie_dict['header']['page_count'] > 0:
                # Each page will have its own dictionary
                self.cookie_dict['header']['pages'] = dict()
                for page in range(self.cookie_dict['header']['page_count']):
                    self.cookie_dict['header']['pages'][page] = page_dict = {}
                    page_dict['page_size'] = unpacker('>i', self.binary_file.read(4))

            # move to first page offset
            for page in range(self.cookie_dict['header']['page_count']):
                # read each page into bytes object
                page_data = self.binary_file.read(self.cookie_dict['header']['pages'][page]['page_size'])
                # now we can process the page
                self.process_page(self.cookie_dict['header']['pages'][page], page_data)

            return self.cookie_dict
        else:
            return False

    def process_page(self, page_dict, page_data):
        page_dict['page_header'] = unpacker('>i', page_data[0:4])
        if page_dict['page_header'] == 256:  # b'00000100'
            page_dict['cookie_count'] = unpacker('<i', page_data[4:8])
            if page_dict['cookie_count'] > 0:
                page_dict['cookies'] = dict()
                s = 8
                for cookie in range(page_dict['cookie_count']):
                    # create a dictionary for each cookie
                    page_dict['cookies'][cookie] = cookie_dict = dict()
                    # get the start offset for each cookie in the page (4 bytes Little Endian)
                    cookie_dict['offset'] = unpacker('<i', page_data[s:s+4])
                    # read the cookie data from the offset
                    cookie_data = page_data[cookie_dict['offset']:]
                    cookie_dict['data'] = self.process_cookie(cookie_data)
                    s += 4

    @staticmethod
    def process_cookie(cookie_data):
        data_dict = dict()
        data_dict['size'] = unpacker('<i', cookie_data[0:4])
        # bytes[4:8] are obscure
        data_dict['flag'] = ''
        # Known flags
        flags = {0: '', 1: 'Secure', 2: 'HTTP', 3: 'Secure/HTTP'}
        if unpacker('<i', cookie_data[8:12]) in flags.keys():
            data_dict['flag'] = flags[unpacker('<i', cookie_data[8:12])]
        # bytes[12:16] are obscure
        # merge output from unpacker with out dictionary
        data_dict = dict(**data_dict, **(unpacker('<4i',
                                                  cookie_data[16:32],
                                                  ['url_ofs', 'name_ofs', 'path_ofs', 'val_ofs'])))
        # miss the following 8 bytes [32:40] - this is the cookie header footer
        data_dict['expires_epoch'] = unpacker('<d', cookie_data[40:48])
        data_dict['last_access_epoch'] = unpacker('<d', cookie_data[48:56])

        # Make the timestamps readable
        data_dict['Expires'] = datetime.fromtimestamp(data_dict['expires_epoch'] +
                                                      cocoa_delta).strftime('%Y-%m-%d %H:%M:%S')
        data_dict['Last Access'] = datetime.fromtimestamp(data_dict['last_access_epoch'] +
                                                          cocoa_delta).strftime('%Y-%m-%d %H:%M:%S')

        # all components end with \x00 so we can use this to delimit the component pieces
        for ofs, component in {'url_ofs': 'URL', 'name_ofs': 'Name', 'path_ofs': 'Path', 'val_ofs': 'Value'}.items():
            s = data_dict[ofs]
            data_dict[component] = ''
            while True:
                # check if \x00
                unpacked_byte = unpacker('<b', cookie_data[s:s+1])
                if unpacked_byte != 0:
                    # append decoded byte to dict
                    data_dict[component] += cookie_data[s:s+1].decode()
                    s += 1
                else:
                    break
        return data_dict


if __name__ == '__main__':
    print("\n\n"
          "                                                        ,%&&,\n"
          "                                                    *&&&&&&&&,\n"
          "                                                  /&&&&&&&&&&&&&\n"
          "                                               #&&&&&&&&&&&&&&&&&&\n"
          "                                           ,%&&&&&&&&&&&&&&&&&&&&&&&\n"
          "                                        ,%&&&&&&&&&&&&&&#  %&&&&&&&&&&,\n"
          "                                     *%&&&&&&&&&&&&&&%       %&&&&&&&&&%,\n"
          "                                   (%&&&&&&&&&&&&&&&&&&&#       %&%&&&&&&&%\n"
          "                               (&&&&&&&&&&&&&&&%&&&&&&&&&(       &&&&&&&&&&%\n"
          "              ,/#%&&&&&&&#(*#&&&&&&&&&&&&&&%,    #&&&&&&&&&(       &&&&&&&\n"
          "          (&&&&&&&&&&&&&&&&&&&&&&&&&&&&&#          %&&&&&&&&&(       %/\n"
          "       (&&&&&&&&&&&&&&&&&&&&&&&&&&&&&(               %&&&&&&&&&/\n"
          "     /&&&&&&&&&&&&&&&&&&%&&&&&&&%&/                    %&&&&&,\n"
          "    #&&&&&&&&&&#          (&&&%*                         #,\n"
          "   #&&&&&&&&&%\n"
          "   &&&&&&&&&&\n"
          "  ,&&&&&&&&&&\n"
          "   %&&&&&&&&&                           {}\n"
          "   (&&&&&&&&&&,             /*          Version: {}\n"             
          "    (&&&&&&&&&&&/        *%&&&&&#\n"
          "      &&&&&&&&&&&&&&&&&&&&&&&&&&&&&%\n"
          "        &&&&&&&&&&&&&&&&&&&&&&&&&%\n"
          "          *%&&&&&&&&&&&&&&&&&&#,\n"
          "                *(######/,".format(__description__, __version__))
    print('\n\n')
    try:
        cookie_file = sys.argv[1]
    except IndexError:
        print('Please provide an input, e.g. python show_me_them_cookies.py Cookies.binarycookies\n')
        sys.exit()

    print('Parsing {}...'.format(cookie_file))
    cookie_dict = CookieParser(cookie_file).process()
    if cookie_dict:
        print('We have cookies! Generating a dataframe...')
        df = pandafy(cookie_dict)
        df.to_csv('binary_cookies.csv')
    else:
        print('No cookies were found in this file.\n')


