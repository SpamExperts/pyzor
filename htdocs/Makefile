# $Id: Makefile,v 1.2 2002-04-16 22:05:36 ftobin Exp $

# Makefile.inc should define
# XSLT_PROG
# because these variables can differ between environments.
include Makefile.inc

XSL          = sourceforge-page.xsl
XSLT_OPTIONS =
XSLT         = $(XSLT_PROG)
PHP          = php -q
ENTITIES     = entities
TIDY         = tidy -config tidyrc -m

NAVBAR_INC         = navbar/navbar.inc-html
NAVBAR_XML         = navbar/navbar.xml
HEAD_BOOKMARKS_INC = navbar/head-bookmarks.inc-html

all : index.html blocking.html

.PHONY : perms

navbar/%.inc-html : navbar/%.xsl $(NAVBAR_XML)
	$(XSLT) -s $< -o $@ $(NAVBAR_XML)

navbar/navbar.xml : $(NAVBAR_XML).php $(ENTITIES)
	$(PHP) $< > $@

%.html : %.xml $(XSL) $(NAVBAR_INC) $(HEAD_BOOKMARKS_INC)
	$(XSLT) -s $(XSL) -o $@ $<
#	$(TIDY) $@

%.xsl : %.xsl.php $(ENTITIES)
	$(PHP) $< > $@

clean :
	find . -name "*html"	| xargs rm -f
	find . -name "*~"	| xargs rm -f

perms :
	chmod -R a+rX .
