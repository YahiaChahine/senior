class array:
    def __init__(self, *args):
        self.__dict = {}
        for key, val in enumerate(args):
            self.__dict[key] = val
    def __getitem__(self, key):
        if key in self.__dict:
            return self.__dict[key]
        else:
            raise IndexError
    def __setitem__(self, key, value):
        if key <= len(self.__dict):
            self.__dict[key] = value
        else:
            raise IndexError
    def __str__(self):
        return str(list(self.__dict.values()))
    
a = array('a','b','c') 			#------output------   [ given specs ]
print(a)   					# ['a', 'b', 'c']
print(a[1])  				# b
a[1] = 'bee'
print(a)     				# ['a', 'bee', 'c']
a[3] = 'day'
print(a)  					# ['a', 'bee', 'c', 'day']
print(a[6])  
