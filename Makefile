#Targets:
#  Default target: build project
#  clean:          remove all generated files.
#  submit:         build compress archive all project source files.
#  run:            execute projec.          

PROJECT = 	p1-npatil5

TARGET =	jar

SRC_FILES = \
p1-npatil5

CFLAGS = -g -Wall -std=c11

$(TARGET):  	
		ant

clean:		
		rm -rf build target $(PROJECT).tar.gz $(PROJECT).jar


submit:
		tar -cvzf $(PROJECT).tar.gz $(SRC_FILES)
run:
		java -cp p1-npatil5.jar RC6 input.txt output.txt
