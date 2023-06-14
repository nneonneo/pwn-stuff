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

//Uses overriding references and the symbolic propogator to resolve system calls
//@category Analysis

import java.io.*;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Predicate;

import generic.jar.ResourceFile;
import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.app.cmd.memory.AddUninitializedMemoryBlockCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.SpaceNames;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.SymbolicPropogator.Value;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This script will resolve system calls for RISCV Linux binaries.
 */
public class ResolveRISCVLinuxSyscallsScript extends GhidraScript {

	private static final String SYSCALL_SPACE_NAME = "syscall";

	private static final int SYSCALL_SPACE_LENGTH = 0x10000;

	//this is the name of the userop (aka CALLOTHER) in the pcode translation of the
	//native "ecall" instruction
	private static final String ECALL_RISCV_CALLOTHER = "ecall";

	//a set of names of all syscalls that do not return
	private static final Set<String> noreturnSyscalls = Set.of("exit", "exit_group");

	//tests whether an instruction is making a system call
	private Predicate<Instruction> tester;

	//register holding the syscall number
	private String syscallRegister;

	//datatype archive containing signature of system calls
	private String datatypeArchiveName;

	//the type of overriding reference to apply 
	private RefType overrideType;

	//the calling convention to use for system calls (must be defined in the appropriate .cspec file)
	private String callingConvention;

	@Override
	protected void run() throws Exception {

		if (!(currentProgram.getExecutableFormat().equals(ElfLoader.ELF_NAME) &&
			currentProgram.getLanguage().getProcessor().toString().equals("RISCV"))) {
			popup("This script is intended for RISC-V Linux files");
			return;
		}

		//determine whether the executable is 32 or 64 bit and set fields appropriately
		int size = currentProgram.getLanguage().getLanguageDescription().getSize();
		if (size == 64) {
			tester = ResolveRISCVLinuxSyscallsScript::checkRISCVInstruction;
			syscallRegister = "a7";
			datatypeArchiveName = "generic_clib_64";
			overrideType = RefType.CALLOTHER_OVERRIDE_CALL;
			callingConvention = "default";
		}
		else {
			tester = ResolveRISCVLinuxSyscallsScript::checkRISCVInstruction;
			syscallRegister = "a7";
			datatypeArchiveName = "generic_clib";
			overrideType = RefType.CALLOTHER_OVERRIDE_CALL;
			callingConvention = "default";
		}

		//get the space where the system calls live.  
		//If it doesn't exist, create it.
		AddressSpace syscallSpace =
			currentProgram.getAddressFactory().getAddressSpace(SYSCALL_SPACE_NAME);
		if (syscallSpace == null) {
			//don't muck with address spaces if you don't have exclusive access to the program.
			if (!currentProgram.hasExclusiveAccess()) {
				popup("Must have exclusive access to " + currentProgram.getName() +
					" to run this script");
				return;
			}
			Address startAddr = currentProgram.getAddressFactory()
					.getAddressSpace(SpaceNames.OTHER_SPACE_NAME)
					.getAddress(0x0L);
			AddUninitializedMemoryBlockCmd cmd = new AddUninitializedMemoryBlockCmd(
				SYSCALL_SPACE_NAME, null, this.getClass().getName(), startAddr,
				SYSCALL_SPACE_LENGTH, true, true, true, false, true);
			if (!cmd.applyTo(currentProgram)) {
				popup("Failed to create " + SYSCALL_SPACE_NAME);
				return;
			}
			syscallSpace = currentProgram.getAddressFactory().getAddressSpace(SYSCALL_SPACE_NAME);
		}
		else {
			printf("AddressSpace %s found, continuing...\n", SYSCALL_SPACE_NAME);
		}

		//get all of the functions that contain system calls
		//note that this will not find system call instructions that are not in defined functions
		Map<Function, Set<Address>> funcsToCalls = getSyscallsInFunctions(currentProgram, monitor);

		if (funcsToCalls.isEmpty()) {
			popup("No system calls found (within defined functions)");
			return;
		}

		//get the system call number at each callsite of a system call.
		//note that this is not guaranteed to succeed at a given system call call site -
		//it might be hard (or impossible) to determine a specific constant
		Map<Address, Long> addressesToSyscalls =
			resolveConstants(funcsToCalls, currentProgram, monitor);

		if (addressesToSyscalls.isEmpty()) {
			popup("Couldn't resolve any syscall constants");
			return;
		}

		//get the map from system call numbers to system call names
		//you might have to create this yourself!
		Map<Long, String> syscallNumbersToNames = getSyscallNumberMap();

		//at each system call call site where a constant could be determined, create
		//the system call (if not already created), then add the appropriate overriding reference
		//use syscallNumbersToNames to name the created functions
		//if there's not a name corresponding to the constant use a default 
		for (Entry<Address, Long> entry : addressesToSyscalls.entrySet()) {
			Address callSite = entry.getKey();
			Long offset = entry.getValue();
			Address callTarget = syscallSpace.getAddress(offset);
			Function callee = currentProgram.getFunctionManager().getFunctionAt(callTarget);
			if (callee == null) {
				String funcName = "syscall_" + String.format("%08X", offset);
				if (syscallNumbersToNames.get(offset) != null) {
					funcName = syscallNumbersToNames.get(offset);
				}
				callee = createFunction(callTarget, funcName);
				callee.setCallingConvention(callingConvention);

				//check if the function name is one of the non-returning syscalls
				if (noreturnSyscalls.contains(funcName)) {
					callee.setNoReturn(true);
				}
			}
			Reference ref = currentProgram.getReferenceManager()
					.addMemoryReference(callSite, callTarget, overrideType, SourceType.USER_DEFINED,
						Reference.MNEMONIC);
			//overriding references must be primary to be active
			currentProgram.getReferenceManager().setPrimary(ref, true);
		}

		//finally, open the appropriate data type archive and apply its function data types
		//to the new system call space, so that the system calls have the correct signatures
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(currentProgram);
		DataTypeManagerService service = mgr.getDataTypeManagerService();
		List<DataTypeManager> dataTypeManagers = new ArrayList<>();
		dataTypeManagers.add(service.openDataTypeArchive(datatypeArchiveName));
		dataTypeManagers.add(currentProgram.getDataTypeManager());
		ApplyFunctionDataTypesCmd cmd = new ApplyFunctionDataTypesCmd(dataTypeManagers,
			new AddressSet(syscallSpace.getMinAddress(), syscallSpace.getMaxAddress()),
			SourceType.USER_DEFINED, false, false);
		cmd.applyTo(currentProgram);
	}

	//TODO: better error checking!
	private Map<Long, String> getSyscallNumberMap() {
		Map<Long, String> syscallMap = new HashMap<>();
		// https://raw.githubusercontent.com/hrw/syscalls-table/master/tables/syscalls-riscv64
		syscallMap.put(202L, "accept");
		syscallMap.put(242L, "accept4");
		syscallMap.put(89L, "acct");
		syscallMap.put(217L, "add_key");
		syscallMap.put(171L, "adjtimex");
		syscallMap.put(200L, "bind");
		syscallMap.put(280L, "bpf");
		syscallMap.put(214L, "brk");
		syscallMap.put(90L, "capget");
		syscallMap.put(91L, "capset");
		syscallMap.put(49L, "chdir");
		syscallMap.put(51L, "chroot");
		syscallMap.put(266L, "clock_adjtime");
		syscallMap.put(114L, "clock_getres");
		syscallMap.put(113L, "clock_gettime");
		syscallMap.put(115L, "clock_nanosleep");
		syscallMap.put(112L, "clock_settime");
		syscallMap.put(220L, "clone");
		syscallMap.put(435L, "clone3");
		syscallMap.put(57L, "close");
		syscallMap.put(436L, "close_range");
		syscallMap.put(203L, "connect");
		syscallMap.put(285L, "copy_file_range");
		syscallMap.put(106L, "delete_module");
		syscallMap.put(23L, "dup");
		syscallMap.put(24L, "dup3");
		syscallMap.put(20L, "epoll_create1");
		syscallMap.put(21L, "epoll_ctl");
		syscallMap.put(22L, "epoll_pwait");
		syscallMap.put(441L, "epoll_pwait2");
		syscallMap.put(19L, "eventfd2");
		syscallMap.put(221L, "execve");
		syscallMap.put(281L, "execveat");
		syscallMap.put(93L, "exit");
		syscallMap.put(94L, "exit_group");
		syscallMap.put(48L, "faccessat");
		syscallMap.put(439L, "faccessat2");
		syscallMap.put(223L, "fadvise64");
		syscallMap.put(47L, "fallocate");
		syscallMap.put(262L, "fanotify_init");
		syscallMap.put(263L, "fanotify_mark");
		syscallMap.put(50L, "fchdir");
		syscallMap.put(52L, "fchmod");
		syscallMap.put(53L, "fchmodat");
		syscallMap.put(55L, "fchown");
		syscallMap.put(54L, "fchownat");
		syscallMap.put(25L, "fcntl");
		syscallMap.put(83L, "fdatasync");
		syscallMap.put(10L, "fgetxattr");
		syscallMap.put(273L, "finit_module");
		syscallMap.put(13L, "flistxattr");
		syscallMap.put(32L, "flock");
		syscallMap.put(16L, "fremovexattr");
		syscallMap.put(431L, "fsconfig");
		syscallMap.put(7L, "fsetxattr");
		syscallMap.put(432L, "fsmount");
		syscallMap.put(430L, "fsopen");
		syscallMap.put(433L, "fspick");
		syscallMap.put(80L, "fstat");
		syscallMap.put(44L, "fstatfs");
		syscallMap.put(82L, "fsync");
		syscallMap.put(46L, "ftruncate");
		syscallMap.put(98L, "futex");
		syscallMap.put(449L, "futex_waitv");
		syscallMap.put(236L, "get_mempolicy");
		syscallMap.put(100L, "get_robust_list");
		syscallMap.put(168L, "getcpu");
		syscallMap.put(17L, "getcwd");
		syscallMap.put(61L, "getdents64");
		syscallMap.put(177L, "getegid");
		syscallMap.put(175L, "geteuid");
		syscallMap.put(176L, "getgid");
		syscallMap.put(158L, "getgroups");
		syscallMap.put(102L, "getitimer");
		syscallMap.put(205L, "getpeername");
		syscallMap.put(155L, "getpgid");
		syscallMap.put(172L, "getpid");
		syscallMap.put(173L, "getppid");
		syscallMap.put(141L, "getpriority");
		syscallMap.put(278L, "getrandom");
		syscallMap.put(150L, "getresgid");
		syscallMap.put(148L, "getresuid");
		syscallMap.put(163L, "getrlimit");
		syscallMap.put(165L, "getrusage");
		syscallMap.put(156L, "getsid");
		syscallMap.put(204L, "getsockname");
		syscallMap.put(209L, "getsockopt");
		syscallMap.put(178L, "gettid");
		syscallMap.put(169L, "gettimeofday");
		syscallMap.put(174L, "getuid");
		syscallMap.put(8L, "getxattr");
		syscallMap.put(105L, "init_module");
		syscallMap.put(27L, "inotify_add_watch");
		syscallMap.put(26L, "inotify_init1");
		syscallMap.put(28L, "inotify_rm_watch");
		syscallMap.put(3L, "io_cancel");
		syscallMap.put(1L, "io_destroy");
		syscallMap.put(4L, "io_getevents");
		syscallMap.put(292L, "io_pgetevents");
		syscallMap.put(0L, "io_setup");
		syscallMap.put(2L, "io_submit");
		syscallMap.put(426L, "io_uring_enter");
		syscallMap.put(427L, "io_uring_register");
		syscallMap.put(425L, "io_uring_setup");
		syscallMap.put(29L, "ioctl");
		syscallMap.put(31L, "ioprio_get");
		syscallMap.put(30L, "ioprio_set");
		syscallMap.put(272L, "kcmp");
		syscallMap.put(294L, "kexec_file_load");
		syscallMap.put(104L, "kexec_load");
		syscallMap.put(219L, "keyctl");
		syscallMap.put(129L, "kill");
		syscallMap.put(445L, "landlock_add_rule");
		syscallMap.put(444L, "landlock_create_ruleset");
		syscallMap.put(446L, "landlock_restrict_self");
		syscallMap.put(9L, "lgetxattr");
		syscallMap.put(37L, "linkat");
		syscallMap.put(201L, "listen");
		syscallMap.put(11L, "listxattr");
		syscallMap.put(12L, "llistxattr");
		syscallMap.put(18L, "lookup_dcookie");
		syscallMap.put(15L, "lremovexattr");
		syscallMap.put(62L, "lseek");
		syscallMap.put(6L, "lsetxattr");
		syscallMap.put(233L, "madvise");
		syscallMap.put(235L, "mbind");
		syscallMap.put(283L, "membarrier");
		syscallMap.put(279L, "memfd_create");
		syscallMap.put(447L, "memfd_secret");
		syscallMap.put(238L, "migrate_pages");
		syscallMap.put(232L, "mincore");
		syscallMap.put(34L, "mkdirat");
		syscallMap.put(33L, "mknodat");
		syscallMap.put(228L, "mlock");
		syscallMap.put(284L, "mlock2");
		syscallMap.put(230L, "mlockall");
		syscallMap.put(222L, "mmap");
		syscallMap.put(40L, "mount");
		syscallMap.put(442L, "mount_setattr");
		syscallMap.put(429L, "move_mount");
		syscallMap.put(239L, "move_pages");
		syscallMap.put(226L, "mprotect");
		syscallMap.put(185L, "mq_getsetattr");
		syscallMap.put(184L, "mq_notify");
		syscallMap.put(180L, "mq_open");
		syscallMap.put(183L, "mq_timedreceive");
		syscallMap.put(182L, "mq_timedsend");
		syscallMap.put(181L, "mq_unlink");
		syscallMap.put(216L, "mremap");
		syscallMap.put(187L, "msgctl");
		syscallMap.put(186L, "msgget");
		syscallMap.put(188L, "msgrcv");
		syscallMap.put(189L, "msgsnd");
		syscallMap.put(227L, "msync");
		syscallMap.put(229L, "munlock");
		syscallMap.put(231L, "munlockall");
		syscallMap.put(215L, "munmap");
		syscallMap.put(264L, "name_to_handle_at");
		syscallMap.put(101L, "nanosleep");
		syscallMap.put(79L, "newfstatat");
		syscallMap.put(42L, "nfsservctl");
		syscallMap.put(265L, "open_by_handle_at");
		syscallMap.put(428L, "open_tree");
		syscallMap.put(56L, "openat");
		syscallMap.put(437L, "openat2");
		syscallMap.put(241L, "perf_event_open");
		syscallMap.put(92L, "personality");
		syscallMap.put(438L, "pidfd_getfd");
		syscallMap.put(434L, "pidfd_open");
		syscallMap.put(424L, "pidfd_send_signal");
		syscallMap.put(59L, "pipe2");
		syscallMap.put(41L, "pivot_root");
		syscallMap.put(289L, "pkey_alloc");
		syscallMap.put(290L, "pkey_free");
		syscallMap.put(288L, "pkey_mprotect");
		syscallMap.put(73L, "ppoll");
		syscallMap.put(167L, "prctl");
		syscallMap.put(67L, "pread64");
		syscallMap.put(69L, "preadv");
		syscallMap.put(286L, "preadv2");
		syscallMap.put(261L, "prlimit64");
		syscallMap.put(440L, "process_madvise");
		syscallMap.put(448L, "process_mrelease");
		syscallMap.put(270L, "process_vm_readv");
		syscallMap.put(271L, "process_vm_writev");
		syscallMap.put(72L, "pselect6");
		syscallMap.put(117L, "ptrace");
		syscallMap.put(68L, "pwrite64");
		syscallMap.put(70L, "pwritev");
		syscallMap.put(287L, "pwritev2");
		syscallMap.put(60L, "quotactl");
		syscallMap.put(443L, "quotactl_fd");
		syscallMap.put(63L, "read");
		syscallMap.put(213L, "readahead");
		syscallMap.put(78L, "readlinkat");
		syscallMap.put(65L, "readv");
		syscallMap.put(142L, "reboot");
		syscallMap.put(207L, "recvfrom");
		syscallMap.put(243L, "recvmmsg");
		syscallMap.put(212L, "recvmsg");
		syscallMap.put(234L, "remap_file_pages");
		syscallMap.put(14L, "removexattr");
		syscallMap.put(276L, "renameat2");
		syscallMap.put(218L, "request_key");
		syscallMap.put(128L, "restart_syscall");
		syscallMap.put(259L, "riscv_flush_icache");
		syscallMap.put(258L, "riscv_hwprobe");
		syscallMap.put(293L, "rseq");
		syscallMap.put(134L, "rt_sigaction");
		syscallMap.put(136L, "rt_sigpending");
		syscallMap.put(135L, "rt_sigprocmask");
		syscallMap.put(138L, "rt_sigqueueinfo");
		syscallMap.put(139L, "rt_sigreturn");
		syscallMap.put(133L, "rt_sigsuspend");
		syscallMap.put(137L, "rt_sigtimedwait");
		syscallMap.put(240L, "rt_tgsigqueueinfo");
		syscallMap.put(125L, "sched_get_priority_max");
		syscallMap.put(126L, "sched_get_priority_min");
		syscallMap.put(123L, "sched_getaffinity");
		syscallMap.put(275L, "sched_getattr");
		syscallMap.put(121L, "sched_getparam");
		syscallMap.put(120L, "sched_getscheduler");
		syscallMap.put(127L, "sched_rr_get_interval");
		syscallMap.put(122L, "sched_setaffinity");
		syscallMap.put(274L, "sched_setattr");
		syscallMap.put(118L, "sched_setparam");
		syscallMap.put(119L, "sched_setscheduler");
		syscallMap.put(124L, "sched_yield");
		syscallMap.put(277L, "seccomp");
		syscallMap.put(191L, "semctl");
		syscallMap.put(190L, "semget");
		syscallMap.put(193L, "semop");
		syscallMap.put(192L, "semtimedop");
		syscallMap.put(71L, "sendfile");
		syscallMap.put(269L, "sendmmsg");
		syscallMap.put(211L, "sendmsg");
		syscallMap.put(206L, "sendto");
		syscallMap.put(237L, "set_mempolicy");
		syscallMap.put(450L, "set_mempolicy_home_node");
		syscallMap.put(99L, "set_robust_list");
		syscallMap.put(96L, "set_tid_address");
		syscallMap.put(162L, "setdomainname");
		syscallMap.put(152L, "setfsgid");
		syscallMap.put(151L, "setfsuid");
		syscallMap.put(144L, "setgid");
		syscallMap.put(159L, "setgroups");
		syscallMap.put(161L, "sethostname");
		syscallMap.put(103L, "setitimer");
		syscallMap.put(268L, "setns");
		syscallMap.put(154L, "setpgid");
		syscallMap.put(140L, "setpriority");
		syscallMap.put(143L, "setregid");
		syscallMap.put(149L, "setresgid");
		syscallMap.put(147L, "setresuid");
		syscallMap.put(145L, "setreuid");
		syscallMap.put(164L, "setrlimit");
		syscallMap.put(157L, "setsid");
		syscallMap.put(208L, "setsockopt");
		syscallMap.put(170L, "settimeofday");
		syscallMap.put(146L, "setuid");
		syscallMap.put(5L, "setxattr");
		syscallMap.put(196L, "shmat");
		syscallMap.put(195L, "shmctl");
		syscallMap.put(197L, "shmdt");
		syscallMap.put(194L, "shmget");
		syscallMap.put(210L, "shutdown");
		syscallMap.put(132L, "sigaltstack");
		syscallMap.put(74L, "signalfd4");
		syscallMap.put(198L, "socket");
		syscallMap.put(199L, "socketpair");
		syscallMap.put(76L, "splice");
		syscallMap.put(43L, "statfs");
		syscallMap.put(291L, "statx");
		syscallMap.put(225L, "swapoff");
		syscallMap.put(224L, "swapon");
		syscallMap.put(36L, "symlinkat");
		syscallMap.put(81L, "sync");
		syscallMap.put(84L, "sync_file_range");
		syscallMap.put(267L, "syncfs");
		syscallMap.put(179L, "sysinfo");
		syscallMap.put(116L, "syslog");
		syscallMap.put(77L, "tee");
		syscallMap.put(131L, "tgkill");
		syscallMap.put(107L, "timer_create");
		syscallMap.put(111L, "timer_delete");
		syscallMap.put(109L, "timer_getoverrun");
		syscallMap.put(108L, "timer_gettime");
		syscallMap.put(110L, "timer_settime");
		syscallMap.put(85L, "timerfd_create");
		syscallMap.put(87L, "timerfd_gettime");
		syscallMap.put(86L, "timerfd_settime");
		syscallMap.put(153L, "times");
		syscallMap.put(130L, "tkill");
		syscallMap.put(45L, "truncate");
		syscallMap.put(166L, "umask");
		syscallMap.put(39L, "umount2");
		syscallMap.put(160L, "uname");
		syscallMap.put(35L, "unlinkat");
		syscallMap.put(97L, "unshare");
		syscallMap.put(282L, "userfaultfd");
		syscallMap.put(88L, "utimensat");
		syscallMap.put(58L, "vhangup");
		syscallMap.put(75L, "vmsplice");
		syscallMap.put(260L, "wait4");
		syscallMap.put(95L, "waitid");
		syscallMap.put(64L, "write");
		syscallMap.put(66L, "writev");
		return syscallMap;
	}

	/**
	 * Scans through all of the functions defined in {@code program} and returns
	 * a map which takes a function to the set of address in its body which contain
	 * system calls
	 * @param program program containing functions
	 * @param tMonitor monitor
	 * @return map function -> addresses in function containing syscalls
	 * @throws CancelledException if the user cancels
	 */
	private Map<Function, Set<Address>> getSyscallsInFunctions(Program program,
			TaskMonitor tMonitor) throws CancelledException {
		Map<Function, Set<Address>> funcsToCalls = new HashMap<>();
		for (Function func : program.getFunctionManager().getFunctionsNoStubs(true)) {
			tMonitor.checkCancelled();
			for (Instruction inst : program.getListing().getInstructions(func.getBody(), true)) {
				if (tester.test(inst)) {
					Set<Address> callSites = funcsToCalls.get(func);
					if (callSites == null) {
						callSites = new HashSet<>();
						funcsToCalls.put(func, callSites);
					}
					callSites.add(inst.getAddress());
				}
			}
		}
		return funcsToCalls;
	}

	/**
	 * Uses the symbolic propogator to attempt to determine the constant value in
	 * the syscall register at each system call instruction
	 * 
	 * @param funcsToCalls map from functions containing syscalls to address in each function of 
	 * the system call
	 * @param program containing the functions
	 * @return map from addresses of system calls to system call numbers
	 * @throws CancelledException if the user cancels
	 */
	private Map<Address, Long> resolveConstants(Map<Function, Set<Address>> funcsToCalls,
			Program program, TaskMonitor tMonitor) throws CancelledException {
		Map<Address, Long> addressesToSyscalls = new HashMap<>();
		Register syscallReg = program.getLanguage().getRegister(syscallRegister);
		for (Function func : funcsToCalls.keySet()) {
			Address start = func.getEntryPoint();
			ContextEvaluator eval = new ConstantPropagationContextEvaluator(monitor, true);
			SymbolicPropogator symEval = new SymbolicPropogator(program);
			symEval.flowConstants(start, func.getBody(), eval, true, tMonitor);
			for (Address callSite : funcsToCalls.get(func)) {
				Value val = symEval.getRegisterValue(callSite, syscallReg);
				if (val == null) {
					createBookmark(callSite, "System Call",
						"Couldn't resolve value of " + syscallReg);
					printf("Couldn't resolve value of " + syscallReg + " at " + callSite + "\n");
					continue;
				}
				addressesToSyscalls.put(callSite, val.getValue());
			}
		}
		return addressesToSyscalls;
	}

	/**
	 * Checks whether an RISC-V instruction is a system call
	 * @param inst instruction to check
	 * @return true precisely when the instruction is a system call
	 */
	private static boolean checkRISCVInstruction(Instruction inst) {
		boolean retVal = false;
		for (PcodeOp op : inst.getPcode()) {
			if (op.getOpcode() == PcodeOp.CALLOTHER) {
				int index = (int) op.getInput(0).getOffset();
				if (inst.getProgram()
						.getLanguage()
						.getUserDefinedOpName(index)
						.equals(ECALL_RISCV_CALLOTHER)) {
					retVal = true;
				}
			}
		}
		return retVal;
	}

}
