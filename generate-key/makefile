src = $(wildcard *.c)
obj = $(src:.c=.o)
dep = $(obj:.o=.d)

CFLAGS = -g -Wall
LDFLAGS = -lcrypto

generate-key: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

-include $(dep)   # include all dep files in the makefile

%.d: %.c
	@$(CPP) $(CFLAGS) $< -MM -MT $(@:.d=.o) >$@

.PHONY: clean
clean:
	rm -f $(obj) generate-key

.PHONY: cleandep
cleandep:
	rm -f $(dep)
