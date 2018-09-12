import idc
import idaapi
import idautils

ea = ScreenEA()
la = SegEnd(ea)

while ea != BADADDR and ea < la:
	ea = NextAddr(ea)
	flags = GetFlags(ea)
	if not isCode(flags):
		flags = MakeCode(ea)