crumbs

2022 - Control-F

Authour/Contact: mike.bangham@controlf.co.uk

Apple Binary Cookie Parser with multiple parsing outputs

Tested on iOS 13.x-15.x.

If you are generating a dataframe you will need to install Pandas. This can be installed using 'pip install pandas'

You will need to extract the Cookies.binarycookies file from the Apple device.

Instructions: 

For a CSV:            'python crumbs.py -i Cookies.binarycookies -o csv'

For a Dataframe:      'python crumbs.py -i Cookies.binarycookies -o df'
