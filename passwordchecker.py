#python script to check the strengh of your password
import re
def check_strength(password):
	score = 0
	if len(password) >= 8:
		score += 1
	if re.search('[a-z]', password):
		score += 1
	if re.search('[A-Z]', password):
		score += 1
	if re.search('[0-9]', password):
		score += 1
	if re.search('[!@#$%^&*]', password):
		score += 1

	if score == 5:
		return("Strong")
	elif score >= 3:
		return("Moderate")
	else:
		return("Weak")
pwd = input("Enter your password to check strength: ")
strength = check_strength(pwd)
print(f"Your password is {strength}")
