src = $(wildcard *.c)
obj = $(src:.c=.o)
dep = $(obj:.o=.d)

CFLAGS = -g -Wall
LDFLAGS = -lcrypto

OPENSSL = openssl

envelop-demo: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

-include $(dep)   # include all dep files in the makefile

%.d: %.c
	@$(CPP) $(CFLAGS) $< -MM -MT $(@:.d=.o) >$@

.PHONY: clean
clean:
	rm -f $(obj) envelop-demo

.PHONY: cleandep
cleandep:
	rm -f $(dep)

id_rsa:
	$(OPENSSL) genpkey -algorithm RSA | tee $@.key | $(OPENSSL) rsa -pubout -out $@.pub
