/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package loader;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Formatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Creates memory maps and disassembles entry points.
 */
public class MB90611Loader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "MB90611 Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, false);

		Set<String> knownHashes = Set.of(
			"7ada3af85dd8dd3f95ca8965ad8e642c26445293", // 29f800t.u4
			"b3a7727544918b9030c362694ddf9a2fc3bca8b4"  // tc538000.u3
		);
		byte[] bytes = provider.readBytes(0, provider.length());
		byte[] hashBytes;
		try {
			hashBytes = MessageDigest.getInstance("SHA-1").digest(bytes);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		String hash;
		try (Formatter formatter = new Formatter()) {
			for (byte b : hashBytes) {
				formatter.format("%02x", b);
			}
			hash = formatter.toString();
		}
		boolean isLoaded = knownHashes.stream().anyMatch(knownHash -> knownHash.equalsIgnoreCase(hash));
		if (isLoaded) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("F2MC:LE:24:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider,
			LoadSpec loadSpec,
			List<Option> options,
			Program program,
			TaskMonitor monitor,
			MessageLog log) throws CancelledException, IOException {
		BinaryReader reader = new BinaryReader(provider, true);
		FlatProgramAPI fpa = new FlatProgramAPI(program, monitor);

		InputStream romStream = provider.getInputStream(0);

		final long cartSize = Math.min(romStream.available(), 0x100000L);
		createSegment(fpa, null,      "PERIPHERALS", 0x000000L, 0x100L,    true, true, false, true, log);
		createSegment(fpa, null,      "RAM",         0x000100L, 0x400L,    true, true, false, true, log);
		createSegment(fpa, null,      "EXT",         0x002000L, 0xEFE000L, true, true, false, true, log);
		createSegment(fpa, romStream, "ROM",         0xF00000L, cartSize,  true, false, true, false, log);

		createNamedData(fpa, program, 0x000001L, "PDR1", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000002L, "PDR2", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000003L, "PDR3", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000004L, "PDR4", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000005L, "PDR5", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000006L, "PDR6", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000007L, "PDR7", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000008L, "PDR8", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000009L, "PDR9", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x00000AL, "PDRA", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000011L, "DDR1", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000012L, "DDR2", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000013L, "DDR3", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000014L, "DDR4", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000015L, "DDR5", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000016L, "ADER", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000017L, "DDR7", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000018L, "DDR8", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000019L, "DDR9", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x00001AL, "DDRA", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000020L, "SMR0", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000021L, "SCR0", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000022L, "SIODR0", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000023L, "SSR0", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000024L, "SMR1", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000025L, "SCR1", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000026L, "SIODR1", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000027L, "SSR1", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000028L, "ENIR", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000029L, "EIRR", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x00002AL, "ELVR", WordDataType.dataType, log);
		createNamedData(fpa, program, 0x00002CL, "ADCS", WordDataType.dataType, log);
		createNamedData(fpa, program, 0x00002EL, "ADCR", WordDataType.dataType, log);
		createNamedData(fpa, program, 0x000030L, "PPGC0", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000031L, "PPGC1", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000034L, "PRL0", WordDataType.dataType, log);
		createNamedData(fpa, program, 0x000036L, "PRL1", WordDataType.dataType, log);
		createNamedData(fpa, program, 0x000038L, "TMCSR0", WordDataType.dataType, log);
		createNamedData(fpa, program, 0x00003AL, "TMR0", WordDataType.dataType, log);
		createNamedData(fpa, program, 0x00003CL, "TMCSR1", WordDataType.dataType, log);
		createNamedData(fpa, program, 0x00003EL, "TMR1", WordDataType.dataType, log);
		createNamedData(fpa, program, 0x000044L, "SMR2", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000045L, "SCR2", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000046L, "SIODR2", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000047L, "SSR2", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000048L, "CSCR0", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000049L, "CSCR1", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x00004AL, "CSCR2", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x00004BL, "CSCR3", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x00004CL, "CSCR4", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x00004DL, "CSCR5", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x00004EL, "CSCR6", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x00004FL, "CSCR7", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000051L, "CDCR0", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000053L, "CDCR1", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x000055L, "CDCR2", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x00009FL, "DIRR", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000A0L, "LPMCR", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000A1L, "CKSCR", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000A5L, "ARSR", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000A6L, "HACR", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000A7L, "ECSR", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000A8L, "WDTC", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000A9L, "TBTC", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000B0L, "ICR00", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000B1L, "ICR01", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000B2L, "ICR02", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000B3L, "ICR03", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000B4L, "ICR04", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000B5L, "ICR05", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000B6L, "ICR06", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000B7L, "ICR07", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000B8L, "ICR08", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000B9L, "ICR09", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000BAL, "ICR10", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000BBL, "ICR11", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000BCL, "ICR12", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000BDL, "ICR13", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000BEL, "ICR14", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0x0000BFL, "ICR15", ByteDataType.dataType, log);

		// BIOS ROM entry point
        for (int i = 0x60; i < 0x100; i += 4) {
			new CreateDataCmd(fpa.toAddr(0xFFFF00 | i), new PointerDataType()).applyTo(program);
		}
		Map <Long, String> mappings = new HashMap<>();
		mappings.put(0x0FFFDCL, "Reset");
		mappings.put(0x0FFFD8L, "INT9");
		mappings.put(0x0FFFD4L, "Exception");
		mappings.put(0x0FFFD0L, "EXT_INT0");
		mappings.put(0x0FFFC8L, "EXT_INT1");
		mappings.put(0x0FFFC0L, "EXT_INT2");
		mappings.put(0x0FFFB8L, "EXT_INT3");
		mappings.put(0x0FFFB0L, "EXT_INT4");
		mappings.put(0x0FFFA8L, "EXT_INT5");
		mappings.put(0x0FFFA0L, "EXT_INT6");
		mappings.put(0x0FFF9CL, "UART0_TX");
		mappings.put(0x0FFF98L, "EXT_INT7");
		mappings.put(0x0FFF94L, "UART1_TX");
		mappings.put(0x0FFF90L, "PPG0");
		mappings.put(0x0FFF8CL, "PPG1");
		mappings.put(0x0FFF88L, "RELOAD_TIMER0");
		mappings.put(0x0FFF84L, "RELOAD_TIMER1");
		mappings.put(0x0FFF80L, "ADC_MEASURE");
		mappings.put(0x0FFF78L, "UART2_TX");
		mappings.put(0x0FFF74L, "TIMER_INTERVAL_INT");
		mappings.put(0x0FFF70L, "UART2_RX");
		mappings.put(0x0FFF68L, "UART1_RX");
		mappings.put(0x0FFF60L, "UART0_RX");
        //mappings.put(0x0FFF54L, "DELAYED_INT");
		mappings.forEach((offset, name) -> {
			try {
                Address entry = fpa.toAddr(0xF00000L | offset);
                fpa.createLabel(entry, name, true);

                long vecOffset = reader.readUnsignedInt(offset) & 0x00FFFFFF;
                if (vecOffset != 0x00FFFFFF) {
                    Address vec = fpa.toAddr(vecOffset);
                    DisassembleCommand cmd = new DisassembleCommand(vec, null, true);
                    cmd.applyTo(program, TaskMonitor.DUMMY);
                    fpa.createFunction(vec, name);
                    if (name.equals("Reset")) {
                        fpa.addEntryPoint(vec);
                    }
                }
			} catch (Exception e) {
				log.appendException(e);
			}
		});

		monitor.setMessage(String.format("%s : Loading done", getName()));
	}

	private void createSegment(FlatProgramAPI fpa,
			InputStream stream,
			String name,
			long address,
			long size,
			boolean read,
			boolean write,
			boolean execute,
			boolean volatil,
			MessageLog log) {
		MemoryBlock block;
		try {
			block = fpa.createMemoryBlock(name, fpa.toAddr(address), stream, size, false);
			block.setRead(read);
			block.setWrite(write);
			block.setExecute(execute);
			block.setVolatile(volatil);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void createNamedData(FlatProgramAPI fpa,
			Program program,
			long address,
			String name,
			DataType type,
			MessageLog log) {
		try {
			if (type.equals(ByteDataType.dataType)) {
				fpa.createByte(fpa.toAddr(address));
			} else if (type.equals(WordDataType.dataType)) {
				fpa.createWord(fpa.toAddr(address));
			} else if (type.equals(DWordDataType.dataType)) {
				fpa.createDWord(fpa.toAddr(address));
			}
			program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void createNamedArray(FlatProgramAPI fpa,
			Program program,
			long address,
			String name,
			int numElements,
			DataType type,
			MessageLog log) {
		try {
			CreateArrayCmd arrayCmd = new CreateArrayCmd(fpa.toAddr(address), numElements, type, type.getLength());
			arrayCmd.applyTo(program);
			program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}

	private void createMirrorSegment(Memory memory,
			FlatProgramAPI fpa,
			String name,
			long src,
			long dst,
			long size,
			MessageLog log) {
		MemoryBlock block;
		Address baseAddress = fpa.toAddr(src);
		try {
			block = memory.createByteMappedBlock(name, fpa.toAddr(dst), baseAddress, size, false);

			MemoryBlock baseBlock = memory.getBlock(baseAddress);
			block.setRead(baseBlock.isRead());
			block.setWrite(baseBlock.isWrite());
			block.setExecute(baseBlock.isExecute());
			block.setVolatile(baseBlock.isVolatile());
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	public class ByteCharSequence implements CharSequence {

		private final byte[] data;
		private final int length;
		private final int offset;

		public ByteCharSequence(byte[] data) {
			this(data, 0, data.length);
		}

		public ByteCharSequence(byte[] data, int offset, int length) {
			this.data = data;
			this.offset = offset;
			this.length = length;
		}

		@Override
		public int length() {
			return this.length;
		}

		@Override
		public char charAt(int index) {
			return (char) (data[offset + index] & 0xff);
		}

		@Override
		public CharSequence subSequence(int start, int end) {
			return new ByteCharSequence(data, offset + start, end - start);
		}
	}
}
