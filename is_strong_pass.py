import re

def is_strong_pass(password):
    # password_regex = re.compile(r'[a-z]+[0-9]+[A-Z]')
    lower_regex = re.compile(r'[a-z]')
    upper_regex = re.compile(r'[A-Z]')
    number_regex = re.compile(r'[0-9]')

    if lower_regex.search(password) and upper_regex.search(password) and number_regex.search(password) and len(password)>=8:
        return True
    else:
        return False


test_1 = is_strong_pass('abcdefgh')
test_2 = is_strong_pass('ABCDEFGH')
test_3 = is_strong_pass('12345678')
test_4 = is_strong_pass('a1Abcdef')
test_5 = is_strong_pass('1234Kkket')
print(test_1)
print(test_2)
print(test_3)
print(test_4)
print(test_5)
test_1
test_2
test_3
test_4
test_5