JFLAGS = -g
JC = javac
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
	ServerCP1.java \
	ClientCP1.java \
	ServerCP2.java \
	ClientCP2.java


default: classes

classes: $(CLASSES:.java=.class)

clean:
	$(RM) *.class
