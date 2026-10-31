// Dump string->function map, callers, and decompilation for selected addresses.
// args: outDir, then one or more "0xADDR" selectors (comma or space separated)
// @category CI3

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;

public class RefDump extends GhidraScript {

	private String kind;
	private String text;

	private boolean readText(Address a, int max) {
		Memory mem = currentProgram.getMemory();
		byte[] buf = new byte[max];
		int n = 0;
		try {
			n = mem.getBytes(a, buf, 0, max);
		}
		catch (Exception e) {
			return false;
		}
		if (n < 4) {
			return false;
		}
		boolean wide = (n >= 6 && buf[1] == 0 && buf[0] >= 0x20 && buf[0] < 0x7f && buf[3] == 0);
		StringBuilder sb = new StringBuilder();
		if (wide) {
			for (int i = 0; i + 1 < n; i += 2) {
				int c = (buf[i] & 0xff) | ((buf[i + 1] & 0xff) << 8);
				if (c == 0) {
					break;
				}
				if (c < 0x20 || c > 0x7e) {
					if (c > 0x7f) {
						return false;
					}
					continue;
				}
				sb.append((char) c);
			}
			if (sb.length() < 4) {
				return false;
			}
			kind = "W";
			text = sb.toString();
			return true;
		}
		for (int i = 0; i < n; i++) {
			int c = buf[i] & 0xff;
			if (c == 0) {
				break;
			}
			if (c < 0x20 || c > 0x7e) {
				return false;
			}
			sb.append((char) c);
		}
		if (sb.length() < 4) {
			return false;
		}
		kind = "A";
		text = sb.toString();
		return true;
	}

	private String sanitize(String name) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);
			sb.append(Character.isLetterOrDigit(c) || c == '_' ? c : '_');
		}
		return sb.toString();
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String outDir = args.length > 0 ? args[0] : ".";
		StringBuilder extraSb = new StringBuilder();
		for (int i = 1; i < args.length; i++) {
			String a = args[i].trim();
			if (a.isEmpty()) {
				continue;
			}
			if (extraSb.length() > 0) {
				extraSb.append(',');
			}
			extraSb.append(a);
		}
		Memory mem = currentProgram.getMemory();
		MemoryBlock rdata = mem.getBlock(".rdata");
		long rStart = rdata.getStart().getUnsignedOffset();
		long rEnd = rdata.getEnd().getUnsignedOffset();
		Listing listing = currentProgram.getListing();

		// targets we want callers for
		Set<Long> want = new LinkedHashSet<Long>();
		for (String x : extraSb.toString().split(",")) {
			x = x.trim();
			if (x.isEmpty()) {
				continue;
			}
			want.add(Long.decode(x));
		}
		Map<Long, List<String>> callers = new LinkedHashMap<Long, List<String>>();
		for (Long l : want) {
			callers.put(l, new ArrayList<String>());
		}

		Map<Long, List<long[]>> strRefs = new LinkedHashMap<Long, List<long[]>>();
		Map<Long, String[]> cache = new LinkedHashMap<Long, String[]>();

		InstructionIterator it = listing.getInstructions(true);
		int ic = 0;
		while (it.hasNext()) {
			Instruction ins = it.next();
			ic++;
			// caller detection
			if (!want.isEmpty()) {
				ghidra.program.model.address.Address[] flows = ins.getFlows();
				if (flows != null) {
					for (Address fa : flows) {
						long t = fa.getUnsignedOffset();
						if (callers.containsKey(t)) {
							Function cf = listing.getFunctionContaining(ins.getAddress());
							String s = String.format("0x%08X in %s", ins.getAddress()
									.getUnsignedOffset(), cf == null ? "?" : cf.getName());
							List<String> lst = callers.get(t);
							if (lst.size() < 40) {
								lst.add(s);
							}
						}
					}
				}
			}
			int nops = ins.getNumOperands();
			Function f = null;
			for (int i = 0; i < nops; i++) {
				Scalar s = ins.getScalar(i);
				if (s == null) {
					continue;
				}
				long v = s.getUnsignedValue();
				if (v < rStart || v > rEnd) {
					continue;
				}
				if (!cache.containsKey(v)) {
					if (readText(toAddr(v), 120)) {
						cache.put(v, new String[] { kind, text });
					}
					else {
						cache.put(v, null);
					}
				}
				String[] st = cache.get(v);
				if (st == null) {
					continue;
				}
				if (f == null) {
					f = listing.getFunctionContaining(ins.getAddress());
					if (f == null) {
						break;
					}
				}
				List<long[]> lst = strRefs.get(v);
				if (lst == null) {
					lst = new ArrayList<long[]>();
					strRefs.put(v, lst);
				}
				lst.add(new long[] { f.getEntryPoint().getUnsignedOffset(),
					ins.getAddress().getUnsignedOffset() });
			}
		}
		println("instructions=" + ic + " uniqueStrings=" + strRefs.size());

		File a2 = new File(outDir, "string_refs.tsv");
		PrintWriter w2 = new PrintWriter(a2, "UTF-8");
		w2.println("funcEntry\tfuncRVA\tfuncName\tstrVA\tkind\ttext");
		int rows = 0;
		for (Map.Entry<Long, List<long[]>> e : strRefs.entrySet()) {
			String[] st = cache.get(e.getKey());
			Set<Long> uniq = new LinkedHashSet<Long>();
			for (long[] r : e.getValue()) {
				uniq.add(r[0]);
			}
			for (Long fe : uniq) {
				Function f = getFunctionAt(toAddr(fe));
				w2.println(String.format("0x%08X\t0x%08X\t%s\t0x%08X\t%s\t%s", fe, fe - 0x400000L,
					f == null ? "?" : f.getName(), e.getKey(), st[0], st[1].replace('\t', ' ')));
				rows++;
			}
		}
		w2.close();
		println("wrote " + a2 + " rows=" + rows);

		File dd = new File(outDir, "decomp");
		dd.mkdirs();
		DecompInterface ifc = new DecompInterface();
		ifc.toggleCCode(true);
		ifc.toggleSyntaxTree(true);
		ifc.openProgram(currentProgram);
		PrintWriter wc = new PrintWriter(new File(outDir, "callers.txt"), "UTF-8");
		for (Long t : want) {
			println(String.format("== 0x%08X ==", t));
			List<String> cl = callers.get(t);
			wc.println(String.format("== 0x%08X ==", t));
			for (String s : cl) {
				println("   caller " + s);
				wc.println("   " + s);
			}
			Address ad = toAddr(t);
			Function f = listing.getFunctionContaining(ad);
			if (f == null) {
				println("   no containing function");
				continue;
			}
			println(String.format("   func %s @ 0x%08X size=%d", f.getName(),
				f.getEntryPoint().getUnsignedOffset(), f.getBody().getNumAddresses()));
			DecompileResults res = ifc.decompileFunction(f, 120, monitor);
			if (res == null || !res.decompileCompleted()) {
				println("   decompile failed");
				continue;
			}
			String fn = String.format("%08X_%s.c", f.getEntryPoint().getUnsignedOffset(),
				sanitize(f.getName()));
			PrintWriter w = new PrintWriter(new File(dd, fn), "UTF-8");
			w.println("// " + f.getName() + " @ 0x" +
				Long.toHexString(f.getEntryPoint().getUnsignedOffset()));
			w.println(res.getDecompiledFunction().getC());
			w.close();
			println("   wrote " + fn);
		}
		wc.close();
		ifc.dispose();
	}
}
