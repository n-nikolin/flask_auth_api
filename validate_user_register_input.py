import re

# CHECK IF STRONG PASSWORD
def is_valid_email_and_password(password, email):
    # combine email and password check in one function with appropriate responses
    def is_strong_password(password):
        # checks if password is strong
        lower_regex = re.compile(r'[a-z]')
        upper_regex = re.compile(r'[A-Z]')
        number_regex = re.compile(r'[0-9]')
        #THIS IS SHIT AND THERE IS A BETTER WAY OF DOING THIS
        if lower_regex.search(password) and upper_regex.search(password) and number_regex.search(password) and len(password)>=8:
            return True
        else:
            return False

    def is_email(email):
        email_regex = re.compile(r'''(
            [a-zA-z0-9._%+-]+   # username
            @                   # @ symbol
            [a-zA-Z0-9.-]+      # domain name
            (\.[a-zA-Z]{2,4})   # dot something
            )''', re.VERBOSE
        )
        if email_regex.search(email):
            return True
        else:
            return False
    
    return  is_strong_password(password), is_email(email)

print(is_valid_email_and_password('keTTama147', 'test@test.com'))