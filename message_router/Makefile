name := forwarder
test := forwarder_test
DEBUG = "DEBUG=0"

CCPP := $(CXX)
cxxflags = --std=c++17 -Wextra -Wall -pthread -D $(DEBUG)

all_cxx_files := $(shell find . -name "*.cpp")
cxx_files := $(filter-out %.t.cpp, $(all_cxx_files))
h_files := $(shell find . -name "*.h")
d_files := $(patsubst %.cpp,%.d,$(all_cxx_files))
md_files := $(patsubst %.cpp,%.md,$(all_cxx_files))
all_cxx_objects := $(patsubst %.cpp,%.o,$(all_cxx_files))
cxx_objects := $(patsubst %.cpp,%.o,$(cxx_files))
pp_files := $(patsubst %, %.PP,$(all_cxx_files) $(h_files))

#cxxflags+= -g
cxxflags+= -O3
cxxflags+= -Winit-self
cxxflags+= -Wno-sign-compare
cxxflags+= -Wdisabled-optimization
cxxflags+= -iquote .
ldflags = -lzmq -lboost_program_options -lstdc++fs
ldflags+= $(LDFLAGS)
dflags = -MP -MF $*.d
#Seems that below magic is needed for static linking with pthreads...
#ldflags+= -lrt -Wl,--whole-archive -lpthread -Wl,--no-whole-archive -static

################################################################################
# Top level targets
################################################################################


$(name): $(cxx_objects)
	$(CCPP) $^ -o $@ $(wxldflags) $(ldflags) $(cxxflags)

docs: SHELL=/bin/bash
docs: $(cxx_files) $(h_files) Doxyfile
	doxygen 2>&1 > >(sed '/^Parsing file/!d; s/^Parsing file //;') |sed '/static_string.h.*warning/d'

doxygen.log: $(cxx_files) $(h_files) Doxyfile
	doxygen > doxygen.log 2>&1 
	
################################################################################
# Dependencies
################################################################################

# md_files are markers of manual deps generation (normally no need for to call
# make deps manually). We use .md files because we need empty dependency on real
# dep files (.d --- see below) but we still want to be able to generate .d files
# manually if somebody really wants it :)
deps: $(md_files)

$(md_files): %.md : %.cpp
	$(CCPP) -MM $(dflags) $(cxxflags) $(wxcflags) $*.cpp
	touch $*.md

# empty dependency list on .d files allows make to ignore single removed
# dependency file despite it being normal prerequisite for .o file
$(d_files):

# Include only existing d_files, missing d_files will trigger rebuild of object
# file anyway because .d file is dependency of .o file
include $(wildcard $(d_files))

################################################################################
# Normal objects
################################################################################

# note that -MMD causes .d file to be generated in addition to .o file
$(all_cxx_objects): %.o : %.cpp %.d Makefile
	$(CCPP) -MMD $(dflags) $(cxxflags) $(wxcflags) -c $*.cpp -o $*.o

$(pp_files): %.PP : %
	$(CCPP) $(cxxflags) $(wxcflags) -E $* > $*.PP

################################################################################
# Utility targets
################################################################################

tags: $(cxx_files) $(h_files) 
	ctags --extra=+fq $(all_cxx_files) $(h_files)

clean:
	rm -f $(all_cxx_objects) $(d_files) $(pp_files)

cleanall: clean
	rm -f $(name) tags
