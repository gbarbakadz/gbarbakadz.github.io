
## Installation / Fundamentals

```
# Installation
$ sudo apt-get install <ruby_version>        # Linux
$ brew install ruby                          # MacOS

# https://www.ruby-lang.org/en/documentation/ruby-from-other-languages/

-----------------------------------------------------------------------------

$ ruby hello.rb             # Ruby from a File
$ ruby -e " puts 'Hello"    # Ruby from Command Line
$ irb                       # Interactive Ruby

#!/usr/bin/ruby             # shebang

-----------------------------------------------------------------------------

# Ruby One-Liners
$ ruby -ep 0 file.txt                            # Display content of file
$ ruby -ne 'END {print "Lines:",$.,"\n"}' file   # Display Number of Lines
$ ruby -i -pe 'gsub "foo","FOO"' file            # Change foo to FOO


------------------------------------------------------------------------------

# Librarys
$ gem list                 # Local Librarys
$ gem install [Library]    # Install Library
$ gem install pry          # Install pry library

-------------------------------------------------------------------------------
```


**Interegers**

```ruby
puts 2+2
puts 3.+3
puts 4.4+5

puts 4.odd?
puts 4.even?
puts 4.next
puts 4.pred

puts 25.to_s
puts 65.chr

```


**Strings**

```ruby

# Quotes
puts %[Hello "World"]
puts %Q[Hello "World"]
puts %q[Hello "World"]


# Info about strings
st = "myString"
st.empty?
st.frozen?
st.clear
st.lenght
st.size
st.start_with? "my"
st.end_with? "ing"



# Heredoc
st = <<END 
and it Heredoc
Script and
awesome
END
puts st



# String Arithmetics
st = "MyString is Perl"
st << "NotMyString"
st * 5
st[Perl] = "Ruby"
st[0] = "m"
st[0..5] = "MyAbs"
st[0..5] = "M"


st.sub("Perl","Ruby")
st.gsub("Perl","Ruby")
st.sub!("Perl","Ruby")
st.gsub!("Perl","Ruby")

st.insert(0,"m")
st.insert(-2,"M")
st.insert(st.size,"World")



# Interpolation
puts "My name is #{Ruby Code}"
puts %[My name is #{Ruby Code}]


# Some Useful Method
st = "Mystring"
st.upcase
st.downcase
st.capitalize
st.reverse
st.chop
```


**Arrays**

```ruby
# Create Array
arr = Array.new(10)
arr = Array.new(10, "HelloWorld")
arr = Array.new(10, 0)

arr2 = Array["Hello", "World"]
arr2 = Array[]
arr2 = []
arr2 << 1 << 2 << 3 << 4 << 5

# Array Class/Format
puts arr.class
puts arr[0].class
puts arr[1].class

# Multi Array
arr = [1, ["Hello", 137], 2 , 3]
arr = [1, [2, ["Hello", 137], 3], 4]


# Variables in Arrays - If Var is changed, Arr is changed and vice verca
var = "Mystring"
arr = [1, var]


# Insertion
arr = [1,3,4,5]
arr.insert(1,2)                        # Prints 1 2 3 4 5
arr.insert(1,2,11,22,33)               # Prints 1 2 11 22 33 3 4 5
arr << 6                               # Append
arr[1..3] = ["two", "three", "four"]


# Deletion
arr = [1,"Hello",3,4,5]
arr.delete_at(0)               # Delete index 0
arr.delete("Hello")            # Delete "Hello"
arr.delete(1)                  # Detele 1


# Operations between arrays
arr1 = [1,2,3]
arr2 = [2,3,4]
arr3 = [5,6,7]
all = arr1 + arr2 + arr3
all = arr1 | arr2                    # No Dublicates
all = arr1 & arr2                    # Common Elements
all = arr1 - arr2                    # Difference



# Stack
arr = [1,"Hello",2,3,4]
arr.push(5)
arr.pop


# Useful Methods
arr.sort
arr.reverse
arr.uniq
arr.sort!                         # Change Original Object
arr.reverse!                      # Change Original Object
arr.uniq!                         # Change Original Object


# Arrays and Strings
arr = ["Hello", "World", "!"]
arr.join(" ")                     # Prints Hello World !

st = "Hello World !"
st.split(" ")                     # Prints ["Hello", "World", "!"]


```


**Ranges and Hash**
```ruby

# Ranges
(2..9).to_a                   # Array from 2 to 9
(2...9).to_a                  # Array from 2 to 8
("a".."z").to_a               # Array from a to z

arr = ("a".."z").to_a         # Arr Variable with array from a to z
arr = ("Hi a".."Hi b").to_a   # Arr Variable with array from Hi a to Hi z

(2..9).begin
(2..9).min
(2..9).max
(2..9).end
(2..9).include?(4)
(2..9) === 4
("a".."z").include?("c")



# Hashes / Dictionaries
hash = {}
hash["a"] = "Hello"
hash["b"] = "World"

hash = {"a" => "Hello", "b" => "World"}
hash = {fname:"Hello", lname:"World"}
hash = {":fname" => "Hello", ":lname" => "World"}


```


## Control Structures

**Comparison**

```ruby

a <=> b
	0 if a == b
	1 if a > b
	-1 if a < b

```


**Conditionals**

```ruby

if x > 0 then
	puts "Done"
elsif x < 10 then
	puts "Undone"
else
	puts "Other"
end


if x > 0 
	puts "Done"
end



# Single line Conditions

if x > 0 then puts "Done" end

puts "\n Done" if a.is_a? Integer
puts "\n Done" if a > 0


# Case

x = 5
case x
	when 1 then print "one"
	when 2 then print "two"
	when 3 then print "three"
	else print " idk"
end



# Ternary Operator

test_expr ? True_expr : false_expr

name == "Someone" ? "Hi Someone" : "Who are you ?"

```



**Loops** 

```ruby

# While
i = 0
while i < 5 do                    # With/Without "do"
	puts i
	i += 1
end


while i < 5 do puts i+=1 end
puts i+=1 while i<5
arr.pop while !arr.empty?


# Until
i = 5
until i == 0 do                   # With/Without "do"
	puts i
	i -= 1
end


until i == 0 do puts i-=1 end
puts i-=1 until i ==0



# For
for i in [2,5,10] do
	puts i
end


for i in 1..10 do
	puts i
end


# Times

n = 5
n.times
	puts "Hello World !"
end

```


**Iterators & Enumerators**

```ruby

# Iterators

arr.each do |i|
	puts i
end


arr.each { |i| puts i }

(1..10).each { |i| puts i }
("a".."z").each { |c| puts c }


4.upto(20) { |n| puts n }
5.downto(-2) { |n| puts n }



# Enumerable Objects

arr = [1,2,5,8,11]

arr.map! do |i|                               # Change Elements of arr
	i*i
end


nums = arr.select do |i|                      # Prints 2,8
	i%2 == 0 
end


nums = arr.reject do |i|                      # Prints 1,5,8,11
	i%2 == 0
end


nums = arr.inject { |sum, x| sum+x }          # Sums array elements



# External Enumerators

arr = [1,2,5,8,11]

enum = arr.to_enum
enum.next                          # Prints 2
enum.next                          # Prints 5
```



**Altering Structured Control Flow**

```ruby

# Break

for i in (1..10)
	print i, "\s"
	break if i==5
end


(1..10).each do |i|
	puts i 
	break if i == 5
end


# Next

for i in (1..10)
	next if i == 5
	print i, "\s"
end


(1..10).each do |i|
	next if i == 5
	puts i, "\s"
end



```


**BEGIN / END**

```ruby


BEGIN {
 puts "\n","Beginning code","\n"
}

END{
 puts "Ending code","\n"
}

puts "Normal control flow","\n"



```


## Methods, Variables, and Scope


**Methods**
```ruby

# Methods

def test(x)
	return x*2
end


# Alias

def my_long_name(X)
	return x
end

alias f my_long_name



# Parameter Default Values

def test(name = "Someone")
	return x
end


# Array as Parameter

def test(x , *arr)
	return x
	return arr
end


# Hashes as Argument

def test(hash)
	return hash[:name]
end

test({:name=>"Someone"})




```


**Variables**

```ruby

puts
# prints the name of the script
puts "Script name:\t\t#{$0}"

# prints the command line arguments
puts "arguments:\t\t#{$*}"

# reads a line and prints it
print "Write something:\t"
$stdin.gets
print "gets:\t\t\t",$_
puts


# Constant A-Z

A = 100
A = 200                               # Error Arised

A = 100
module B
	A = 200
end

puts A
puts B::A


```



## Classes, Modules, and Exceptions

#### **Classes Principles**

**Clasess**

```ruby

class MyClass
	def func
		return True
	end

end

myobj = MyClass.new
myobj.func



```


**Instance Variables**

```ruby

class MyClass
	@a = 1000
	def func
		return @a
	end

end

myobj = MyClass.new
myobj.func                        # Prints nothing, @a is Myclass Instance


class MyClass
	def func1
		@a = 1000
	end
	def func2
		puts @a                 
	end
end

myobj = MyClass.new
myobj.func2                      # Prints 1000, Because @a is in same instance


```


**Getter/Setter** 
```ruby

# Get/Set

class MyClass
	attr_accessor :x,:y
	
end

myobj = MyClass.new
myobj.x = 100
myobj.y = 200
puts myobj.x, myobj.y



# Get

class MyClass
	attr_reader :x,:y
	
end

myobj = MyClass.new(100,200)
puts myobj.x, myobj.y

```


**Class Methods**
```ruby

class MyClass
	def self.func
		puts "Hello World !"
	end
end


puts Myclass.func


```


**initialize methods**
```ruby

class MyClass
	attr_accessor :x,:y

	def initialize(x,y)
		@x = x
		@y = y
	end

	def sum
		puts @x + @y
	end
	
end

obj = MyClass.new(10,20)
obj.sum

```


**Open Classes**
```ruby

class String
	def dsize
		self.size *2
	end
end

puts "Hello".dsize
```



#### Method Visibility


**Private Methods**
```ruby

class MyClass
	def func
		return func
	end

	private

	def privatefunc
		puts "Private Func"
	end
end

```

```ruby


class MyClass
	def func
		return func
	end

	def privatefunc
		puts "Private Func"
	end

	private:privatefunc
	
end

```

```ruby

class MyClass
	def self.func
		return func
	end

	def self.privatefunc
		puts "Private Func"
	end

	private_class_method:privatefunc
	
end
```



**Protected Methods**

```ruby

# Protected Methods work as private but protected method may be called by any instances of the defining class or its subclasses

class MyClass
	def func
		return func
	end

	protected       

	def privatefunc
		puts "Private Func"
	end
end

```




#### **Subclassing & Inheritance**

```ruby


class MyClass
	attr_accessor :name

	def initialize(name)
		@name = name
	end

	def to_s
		"i am #{name}"
	end
end


class RootClass < MyClass
obj = RootClass.new("Someone")
obj.to_s

```



#### Modules

**Modules**

```ruby

module MyMath
	PI = 3.14
	E = 2.72

	def self.calc(x)
		return E**x
	end
	
	def self.calc2(x)
		return PI**x
	end


end

puts MyMath.calc(5)
puts MyMath.calc2(5)

```



**Mixin**

```ruby

module B
	def hello
		return "Hello"
	end
end

class A
	include B
	def world
		return "World"
	end
end

obj = A.new
puts obj.hello, " ", obj.world


```


```ruby

include Math
puts PI
puts E
puts sqrt(25)

```


#### Exception

```ruby
def my_method(a,b,c)
	# normal flow
rescue
	# exception handling
else
	# no exception occur
ensure
	# alwys executed

```

```ruby
begin
	# normal flow
rescue
	# exception handling
else
	# no exception occur
ensure
	# alwys executed
```

**Exception**
```ruby

begin
	print 1/0
rescue
	print("Error Occourd")
end

```


**Retry**
```ruby

begin
	print 1/0
rescue
	print("Error Occourd")
	retry
end


```


**Ensure**
```ruby

begin
	print 1/0
rescue
	print("Error Occourd")
ensure
	puts("Alwys Executed")
end
```






## Pentesters Prerequisites

#### **Regex**

```ruby

st = "Mystring is a stringA"
st =~ /Mystring/              # Regex Match
st =~ %r(Mystring)            # Regex Match
st =~ /Mystring/i             # Case Insensitive Match


/Mystring/.match(st)          # Regex Match
/mystring/i.matchst)         # Regex Match

matching = /Mystring/.match(st)           # Regex Match
matching = /Mystring/i.match(st)          # Regex Match
matching[0]

st" =~ /\(/              # Regex Match find (
st" =~ /\)/              # Regex Match find )
st =~ /\|/               # Regex Match find |


st =~ /[0-9]/            # digit
st =~ /[\d]/             # digit
st =~ /[\D]/             # no digit
st =~ /[\w]/             # word
st =~ /[\W]/             # no word
st =~ /[\s]/             # space
st =~ /[\S]/             # no space


"Code: 4B" =~ /\d[A-Z]/               # prints 6, match 4B

st =~ /strex|string/i                 # Alternatives
st =~ /strin(g|n)/                    # alternatives

st =~ /string{2}/                     # Occurance twice
st =~ /^Mystring/                     # Start with "Mystring"
st =~ /string$/                       # end with "string"


ip = /\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/.match("This is my ip 192.168.10.1")  # Regex IP
ip[0]                                                                       # get IP


```

**Global Variables**
```ruby

string = "This is my ip 192.168.10.1"
string =~ /\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/
$~                                          # matchdata object
$&                                          # prints searched string (192.168.10.1)
$1                                          # prints word after space
$2                                          # so on...
$~.to_s                                     # to string
```

**Working with Strings**
```ruby

text = "abcd 192.168.10.1 this is my ip 192.168.20.110"
pattern = /\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/

text.scan(pattern) { |x| puts x}                 # prints all ip

```

#### Time

**Time**
```ruby

Time.now                    # Current time
Time.now.utc                # Currnet time in UTC

t = Time.local(2014,1,13,11,50)         # Set new time
t.year
t.month
t.day

```



#### Files and Directories

**Directories**
```ruby

Dir.pwd                  # Current directory
Dir.getwd                # Current directory
Dir.home("user")         # Home directory of user

# Change Directory
Dir.chdir("/tmp")
Dir.chdir("..")

Dir.chdir("/tmp") do
	puts Dir.pwd
	Code Here
end


# Create/Delete Directory
Dir.mkdir("test")                  # Create
Dir.unlink("test")                 # Delete


# Directory Listing
Dir.entries(".")
Dir["*.rb]

Dir.foreach(".") do |file|
	puts file
end


# Existence
Dir.exist? "/tmp"

```


**Real World - Check if Application Exist**
```ruby
#!/usr/bin/ruby

directories = [
'C:\\Program FIles\\',
'C:\\Program FIles (x86)\\',
'C:\\'
]

installed = false

for dir in directories do
  dir = dir + ARGV[0]
  if Dir.exist? dir
    installed = true
    puts %Q! Exist : #{dir}!
    puts "\nListing"
    Dir.foreach(".") { |x| puts x }
  end
end

```


**Files**

```ruby

File.exist? "example.txt"            # Existence
File.size? "example.txt"             # Size
File.file? "example.txt"             # Check file
File.directory? "exampledir"         # Check Directory
File.ftype "example.txt"            # Prints file type

File.readable? "exmaple.txt"         # Check readable permission
File.writable? "example.txt"         # Check writable permission
File.executable? "example.txt"       # Check executable permission

File.mtime "example.txt"             # Check last modification time
File.atime "example.txt"             # Check last access time
File.ctime "example.txt"             # Creation time

st = File.stat "example.txt"
st.size
st.mtime
st.ctime
```


**Names**

```ruby

path = "/home/user/flag.txt"

File.basename path                    # return flag.txt
File.basename(path, ".txt")           # return flag

File.dirname path                     # return /home/user
File.extname path	              # return .txt
File.split path                       # return ["/home/user/","flag.txt"]
File.expand_path("~Desktop")          # return /home/user/Desktop

```

**Creation/Deletion/Renaming**

```ruby

File.open("newfile.txt","w")          # Create file
File.new("newfile.txt","w")           # Create file

File.rename("file.txt","renamedfile.txt")          # rename file

File.delete("file.txt")          # Delete file
File.unlink("file.txt")          # Delete file

File.chmod(0777, "file.txt")          # Change permission file

```





## Input Output



**File Stream**

**Read file**
```ruby

# Open and Read file
File.open("example.txt" ,"r") do | file|
	contents = file.read
	puts contents
end



# Read Without Open
content = File.read("example.txt") 
puts content


# As Array
content = File.readlines("example.txt") 
puts content[0]
```


**Write File**
```ruby

# Create/Write File
File.open("example.txt", "w") do |line|
	line.puts("hacked")
end


File.open("example.txt", "w") do |line|
	line.write("hacked")
end


# Append/Write file
File.open("example.txt", "a") do |line|
	line.puts("hacked")
end


File.open("example.txt", "a") do |line|
	line.write("hacked")
end
```




