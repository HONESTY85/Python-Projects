#am creating a triangle tree
def triangle(height):
    lenght = height * 2 - 1
    stars = 1
    for i in range(1, (height + 1)):
        print(("*" * stars).center(lenght))
        stars += 2
    print("*".center(lenght))

triangle(21)
triangle(5)           
