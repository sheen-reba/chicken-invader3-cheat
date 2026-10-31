// Map vtables in .rdata to the code that references them (constructor / factory).
// @category CI3

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;

public class Vtables extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String outDir = args.length > 0 ? args[0] : ".";
		Memory mem = currentProgram.getMemory();
		MemoryBlock text = mem.getBlock(".text");
		MemoryBlock rdata = mem.getBlock(".rdata");
		long tStart = text.getStart().getUnsignedOffset();
		long tEnd = text.getEnd().getUnsignedOffset();
		long rStart = rdata.getStart().getUnsignedOffset();
		long rEnd = rdata.getEnd().getUnsignedOffset();

		// 1. find vtable runs in .rdata
		List<long[]> vt = new ArrayList<long[]>();
		long runStart = -1;
		int runLen = 0;
		for (long a = rStart; a + 4 <= rEnd; a += 4) {
			long v = -1;
			try {
				v = mem.getInt(toAddr(a)) & 0xFFFFFFFFL;
			}
			catch (Exception e) {
				v = -1;
			}
			boolean isCode = v >= tStart && v < tEnd;
			if (isCode) {
				if (runLen == 0) {
					runStart = a;
				}
				runLen++;
			}
			else {
				if (runLen >= 4) {
					vt.add(new long[] { runStart, runLen });
				}
				runLen = 0;
			}
		}
		if (runLen >= 4) {
			vt.add(new long[] { runStart, runLen });
		}
		println("vtable candidates: " + vt.size());

		// 2. map vtable address -> referencing instruction sites (single pass)
		java.util.Set<Long> want = new java.util.LinkedHashSet<Long>();
		for (long[] r : vt) {
			want.add(r[0]);
		}
		Map<Long, List<Long>> refs = new LinkedHashMap<Long, List<Long>>();
		Listing listing = currentProgram.getListing();
		InstructionIterator it = listing.getInstructions(true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			int n = ins.getNumOperands();
			for (int i = 0; i < n; i++) {
				Scalar s = ins.getScalar(i);
				if (s == null) {
					continue;
				}
				long v = s.getUnsignedValue();
				if (!want.contains(v)) {
					continue;
				}
				List<Long> lst = refs.get(v);
				if (lst == null) {
					lst = new ArrayList<Long>();
					refs.put(v, lst);
				}
				lst.add(ins.getAddress().getUnsignedOffset());
			}
		}

		// 3. write report
		File f = new File(outDir, "vtables.tsv");
		PrintWriter w = new PrintWriter(f, "UTF-8");
		w.println("vtableVA\tvtableRVA\tentries\tfirstEntries\trefSites\trefFuncs");
		for (long[] r : vt) {
			long va = r[0];
			int len = (int) r[1];
			List<Long> rs = refs.get(va);
			StringBuilder sites = new StringBuilder();
			StringBuilder funcs = new StringBuilder();
			if (rs != null) {
				int c = 0;
				for (Long s : rs) {
					if (c++ > 6) {
						break;
					}
					if (sites.length() > 0) {
						sites.append(';');
					}
					sites.append(String.format("0x%08X", s));
					Function fn = listing.getFunctionContaining(toAddr(s));
					if (funcs.length() > 0) {
						funcs.append(';');
					}
					funcs.append(fn == null ? "?" : fn.getName());
				}
			}
			StringBuilder fe = new StringBuilder();
			for (int k = 0; k < Math.min(4, len); k++) {
				try {
					long v = mem.getInt(toAddr(va + 4L * k)) & 0xFFFFFFFFL;
					if (fe.length() > 0) {
						fe.append(',');
					}
					fe.append(String.format("0x%08X", v));
				}
				catch (Exception e) {
					break;
				}
			}
			w.println(String.format("0x%08X\t0x%08X\t%d\t%s\t%s\t%s", va, va - 0x400000L, len,
				fe, sites, funcs));
		}
		w.close();
		println("wrote " + f.getAbsolutePath());

		// 4. quick lookup of specific vtables passed in args[1..]
		for (int i = 1; i < args.length; i++) {
			String a = args[i].trim();
			if (a.isEmpty()) {
				continue;
			}
			Address ad = toAddr(Long.decode(a));
			long v = mem.getInt(ad) & 0xFFFFFFFFL;
			Function fn = listing.getFunctionContaining(toAddr(v));
			println(String.format("%s -> first entry 0x%08X = %s", a, v,
				fn == null ? "?" : fn.getName()));
		}
	}
}
