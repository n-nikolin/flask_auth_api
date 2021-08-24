import re

def is_email(email):
    email_regex = re.compile(r'''(
        [a-zA-z0-9._%+-]+   # username
        @                   # @ symbol
        [a-zA-Z0-9.-]+      # domain name
        (\.[a-zA-Z]{2,4})   # dot something
        )''', re.VERBOSE
    )
    if email_regex.search(email):
        print('yep, that is definetely an email')
    else:
        print('faggot')

is_email('a@a.com')
is_email('a@a111.com')