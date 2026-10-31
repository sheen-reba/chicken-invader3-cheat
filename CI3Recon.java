// Recover symbols for Chicken Invaders 3 from "Class::method" assert strings.
// - renames the containing function of each symbol string
// - maps every referenced .rdata string to its containing function
// - dumps decompiled C for all renamed functions (+ extra addresses)
// @category CI3
// @keybinding
// @menupath
// @toolbar

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
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

public class CI3Recon extends GhidraScript {

	private static class StrInfo {
		String kind;
		String text;
		StrInfo(String k, String t) { kind = k; text = t; }
	}

	private static String sanitize(String name) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);
			if (Character.isLetterOrDigit(c) || c == '_') {
				sb.append(c);
			}
			else if (c == ':') {
				// collapse "::" into "__"
				if (sb.length() > 0 && sb.charAt(sb.length() - 1) != '_') {
					sb.append('_');
				}
			}
			else {
				sb.append('_');
			}
		}
		String s = sb.toString();
		while (s.contains("__")) {
			s = s.replace("__", "_");
		}
		return s;
	}

	private StrInfo readText(Address a, int max) {
		Memory mem = currentProgram.getMemory();
		byte[] buf = new byte[max];
		int n = 0;
		try {
			n = mem.getBytes(a, buf, 0, max);
		}
		catch (Exception e) {
			return null;
		}
		if (n < 4) {
			return null;
		}
		// wide (UTF-16LE) test
		boolean wide = false;
		if (n >= 6 && buf[1] == 0 && buf[0] >= 0x20 && buf[0] < 0x7f && buf[3] == 0) {
			wide = true;
		}
		StringBuilder sb = new StringBuilder();
		if (wide) {
			for (int i = 0; i + 1 < n; i += 2) {
				int c = (buf[i] & 0xff) | ((buf[i + 1] & 0xff) << 8);
				if (c == 0) {
					break;
				}
				if (c < 0x20 || c > 0x7e) {
					if (c < 0x100 && c >= 0x20) { continue; }
					return null;
				}
				sb.append((char) c);
			}
			if (sb.length() < 4) {
				return null;
			}
			return new StrInfo("W", sb.toString());
		}
		for (int i = 0; i < n; i++) {
			int c = buf[i] & 0xff;
			if (c == 0) {
				break;
			}
			if (c < 0x20 || c > 0x7e) {
				return null;
			}
			sb.append((char) c);
		}
		if (sb.length() < 4) {
			return null;
		}
		return new StrInfo("A", sb.toString());
	}

	private String hexSig(Function f, int len) {
		try {
			byte[] b = new byte[len];
			int n = currentProgram.getMemory().getBytes(f.getEntryPoint(), b, 0, len);
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < n; i++) {
				sb.append(String.format("%02X", b[i] & 0xff));
			}
			return sb.toString();
		}
		catch (Exception e) {
			return "";
		}
	}

	private String addr(long v) {
		return String.format("0x%08X", v);
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String csvPath = args.length > 0 ? args[0] : "";
		String outDir = args.length > 1 ? args[1] : ".";
		String extra = args.length > 2 ? args[2] : "";

		// ---- 1. load symbol CSV (Name,RVA,VA) ----
		Map<Long, String> vaToName = new LinkedHashMap<Long, String>();
		if (!csvPath.isEmpty()) {
			BufferedReader br = new BufferedReader(
				new FileReader(csvPath, StandardCharsets.UTF_8));
			String line;
			boolean first = true;
			while ((line = br.readLine()) != null) {
				if (first) {
					first = false;
					if (line.toLowerCase().startsWith("\"name\"")) {
						continue;
					}
				}
				line = line.trim();
				if (line.isEmpty()) {
					continue;
				}
				String[] p = line.split(",");
				if (p.length < 3) {
					continue;
				}
				String name = p[0].trim().replace("\"", "");
				long va;
				try {
					va = Long.decode(p[2].trim().replace("\"", ""));
				}
				catch (Exception e) {
					continue;
				}
				vaToName.put(va, name);
			}
			br.close();
		}
		println("loaded symbols: " + vaToName.size() + " from " + csvPath);

		Memory mem = currentProgram.getMemory();
		MemoryBlock rdata = mem.getBlock(".rdata");
		if (rdata == null) {
			println("ERROR: no .rdata block");
			return;
		}
		long rStart = rdata.getStart().getUnsignedOffset();
		long rEnd = rdata.getEnd().getUnsignedOffset();
		println(String.format(".rdata 0x%08X - 0x%08X", rStart, rEnd));

		// ---- 2. scan instructions once: scalar operands pointing into .rdata ----
		Listing listing = currentProgram.getListing();
		InstructionIterator it = listing.getInstructions(true);
		// stringVA -> list of "funcEntry|insnAddr"
		Map<Long, List<long[]>> strRefs = new LinkedHashMap<Long, List<long[]>>();
		Map<String, StrInfo> strCache = new LinkedHashMap<String, StrInfo>();
		int insnCount = 0;
		int hitCount = 0;
		while (it.hasNext()) {
			Instruction ins = it.next();
			insnCount++;
			int nops = ins.getNumOperands();
			for (int i = 0; i < nops; i++) {
				Scalar s = ins.getScalar(i);
				if (s == null) {
					continue;
				}
				long v = s.getUnsignedValue();
				if (v < rStart || v > rEnd) {
					continue;
				}
				Address sa = toAddr(v);
				String key = sa.toString();
				if (!strCache.containsKey(key)) {
					strCache.put(key, readText(sa, 120));
				}
				if (strCache.get(key) == null) {
					continue;
				}
				Function f = listing.getFunctionContaining(ins.getAddress());
				if (f == null) {
					continue;
				}
				hitCount++;
				List<long[]> lst = strRefs.get(v);
				if (lst == null) {
					lst = new ArrayList<long[]>();
					strRefs.put(v, lst);
				}
				lst.add(new long[] { f.getEntryPoint().getUnsignedOffset(),
					ins.getAddress().getUnsignedOffset() });
			}
		}
		println("instructions=" + insnCount + " rdata-string refs=" + hitCount + " unique strings=" +
			strRefs.size());

		// ---- 3. rename functions of symbol strings ----
		Map<Long, Function> symbolFuncs = new LinkedHashMap<Long, Function>();
		Map<Long, String> finalNames = new LinkedHashMap<Long, String>();
		int renamed = 0;
		int missing = 0;
		Set<String> used = new LinkedHashSet<String>();
		for (Map.Entry<Long, String> e : vaToName.entrySet()) {
			long sva = e.getKey();
			String name = e.getValue();
			List<long[]> refs = strRefs.get(sva);
			if (refs == null || refs.isEmpty()) {
				missing++;
				continue;
			}
			long fe = refs.get(0)[0];
			Function f = getFunctionAt(toAddr(fe));
			if (f == null) {
				missing++;
				continue;
			}
			symbolFuncs.put(sva, f);
			String cur = f.getName();
			if (cur.startsWith("FUN_") || cur.startsWith("thunk_FUN_")) {
				String base = sanitize(name);
				String cand = base;
				int k = 2;
				while (used.contains(cand) || getGlobalFunctions(cand).size() > 0) {
					cand = base + "_" + k;
					k++;
				}
				if (k == 2) {
					try {
						f.setName(cand, ghidra.program.model.symbol.SourceType.USER_DEFINED);
						used.add(cand);
						renamed++;
						finalNames.put(sva, cand);
					}
					catch (Exception ex) {
						finalNames.put(sva, cur);
					}
				}
				else {
					finalNames.put(sva, cand);
				}
			}
			else {
				used.add(cur);
				finalNames.put(sva, cur);
			}
		}
		println("renamed=" + renamed + " missingRefs=" + missing);

		// ---- 4. write symbols_resolved.tsv ----
		File a1 = new File(outDir, "symbols_resolved.tsv");
		PrintWriter w1 = new PrintWriter(a1, "UTF-8");
		w1.println(
			"symbol\tstrVA\tfuncEntry\tfuncRVA\tfuncName\tfuncSize\trefCount\trefAddrs\tsig24");
		for (Map.Entry<Long, String> e : vaToName.entrySet()) {
			long sva = e.getKey();
			Function f = symbolFuncs.get(sva);
			List<long[]> refs = strRefs.get(sva);
			String rc = refs == null ? "0" : String.valueOf(refs.size());
			StringBuilder ra = new StringBuilder();
			if (refs != null) {
				for (long[] r : refs) {
					if (ra.length() > 0) {
						ra.append(';');
					}
					ra.append(addr(r[1]));
				}
			}
			if (f == null) {
				w1.println(e.getValue() + "\t" + addr(sva) + "\t\t\t\t\t" + rc + "\t" + ra +
					"\t");
				continue;
			}
			long fe = f.getEntryPoint().getUnsignedOffset();
			w1.println(e.getValue() + "\t" + addr(sva) + "\t" + addr(fe) + "\t" +
				addr(fe - 0x400000L) + "\t" + finalNames.get(sva) + "\t" + f.getBody().getNumAddresses() +
				"\t" + rc + "\t" + ra + "\t" + hexSig(f, 24));
		}
		w1.close();
		println("wrote " + a1.getAbsolutePath());

		// ---- 5. write string_refs.tsv (string -> containing function) ----
		File a2 = new File(outDir, "string_refs.tsv");
		PrintWriter w2 = new PrintWriter(a2, "UTF-8");
		w2.println("funcEntry\tfuncRVA\tfuncName\tstrVA\tkind\ttext");
		int rows = 0;
		for (Map.Entry<Long, List<long[]>> e : strRefs.entrySet()) {
			long sva = e.getKey();
			StrInfo si = strCache.get(String.format("0x%08x", sva));
			if (si == null) {
				continue;
			}
			StringBuilder fs = new StringBuilder();
			for (long[] r : e.getValue()) {
				long fe = r[0];
				if (fs.length() > 0) {
					fs.append(';');
				}
				fs.append(addr(fe));
			}
			String[] parts = fs.toString().split(";");
			for (String p : parts) {
				Function f = getFunctionAt(toAddr(Long.decode(p)));
				String fn = f == null ? "" : f.getName();
				w2.println(p + "\t" + addr(Long.decode(p) - 0x400000L) + "\t" + fn + "\t" +
					addr(sva) + "\t" + si.kind + "\t" + si.text.replace("\t", " "));
				rows++;
			}
		}
		w2.close();
		println("wrote " + a2.getAbsolutePath() + " rows=" + rows);

		// ---- 6. decompile ----
		File dd = new File(outDir, "decomp");
		dd.mkdirs();
		DecompInterface ifc = new DecompInterface();
		ifc.toggleCCode(true);
		ifc.toggleSyntaxTree(true);
		if (!ifc.openProgram(currentProgram)) {
			println("decompiler failed to open");
			return;
		}
		Set<Long> targets = new LinkedHashSet<Long>();
		for (Function f : symbolFuncs.values()) {
			targets.add(f.getEntryPoint().getUnsignedOffset());
		}
		if (!extra.isEmpty()) {
			for (String x : extra.split(",")) {
				x = x.trim();
				if (x.isEmpty()) {
					continue;
				}
				targets.add(Long.decode(x));
			}
		}
		int ok = 0;
		int fail = 0;
		for (long fe : targets) {
			Function f = getFunctionAt(toAddr(fe));
			if (f == null) {
				fail++;
				continue;
			}
			DecompileResults res;
			try {
				res = ifc.decompileFunction(f, 90, monitor);
			}
			catch (Exception ex) {
				fail++;
				continue;
			}
			if (res == null || !res.decompileCompleted()) {
				fail++;
				continue;
			}
			String c = res.getDecompiledFunction().getC();
			String fn = String.format("%08X_%s.c", fe, sanitize(f.getName()));
			PrintWriter w = new PrintWriter(new File(dd, fn), "UTF-8");
			w.println("// " + f.getName() + " @ " + addr(fe) + "  (RVA " + addr(fe - 0x400000L) +
				")");
			w.println(c);
			w.close();
			ok++;
		}
		ifc.dispose();
		println("decompiled ok=" + ok + " fail=" + fail + " -> " + dd.getAbsolutePath());
	}
}
