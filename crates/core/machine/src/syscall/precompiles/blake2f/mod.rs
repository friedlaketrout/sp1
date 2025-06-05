mod air;
pub mod columns;
mod trace;

#[derive(Default)]
pub struct Blake2fCompressChip;

impl Blake2fCompressChip {
    
    pub const fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod tests {
    use sp1_core_executor::events::SyscallEvent;
    use sp1_core_executor::{syscalls::SyscallCode, Instruction, Opcode, Program};
    use sp1_stark::CpuProver;
    use test_artifacts::BLAKE2F_COMPRESS_ELF;
    use sp1_core_executor::Executor;
    use sp1_stark::SP1CoreOpts;

    use super::*;
    use sp1_core_executor::events::{Blake2fCompressEvent, MemoryReadRecord, MemoryWriteRecord, MemoryLocalEvent, MemoryRecord, PrecompileEvents, Mutation};

    use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;
    use sp1_core_executor::ExecutionRecord;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_baby_bear::BabyBear;

    use sp1_stark::air::MachineAir;
    use sp1_stark::MachineProver;
    use sp1_stark::StarkGenericConfig;

    use crate::{syscall, utils};
    use crate::{
        io::SP1Stdin,
        riscv::RiscvAir,
        utils::{run_test, setup_logger, uni_stark_prove as prove, uni_stark_verify as verify},
    };

    #[test]
    fn test_blake2f_compress_program() {
        setup_logger();
        let program = Program::from(BLAKE2F_COMPRESS_ELF).unwrap();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
    }

    #[test]
    fn test_blake2f_compress_program_prove() {
        utils::setup_logger();
        let program = Program::from(BLAKE2F_COMPRESS_ELF).unwrap();
        let stdin = SP1Stdin::new();
        utils::run_test::<CpuProver<_, _>>(program, stdin).unwrap();
    }
    
    #[test]
    fn test_blake2f_compress_event() {
        let event = Blake2fCompressEvent {
            shard: 1,
            clk: 36932,
            base_ptr: 2097860,
            rounds: 1,
            h: [7640891576939301192, 13503953896175478587, 4354685564936845355, 11912009170470909681, 5840696475078001361, 11170449401992604703, 2270897969802886507, 6620516959819538809],
            m: [6513249, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            t0: 3,
            t1: 0,
            f: true,
            result: [13130869290738220370, 1843283218530184216, 1972440628803554304, 2771940763792691963, 11912500024367107573, 17507708957921458467, 16014066886824952654, 8177290712754660385],
            mutations: vec![
                Mutation {v: [7640891576939301192, 13503953896175478587, 4354685564936845355, 11912009170470909681, 5840696475078001361, 11170449401992604703, 2270897969802886507, 6620516959819538809, 7640891576956012808, 13503953896175478587, 4354685564936845355, 11912009170470909681, 5840696475078001362, 11170449401992604703, 16175846103906665108, 6620516959819538809], compress_intermediaries: None, final_v_xor: None},
                Mutation {v: [17350586023075716586, 13503953896175478587, 4354685564936845355, 11912009170470909681, 13249304492735193375, 11170449401992604703, 2270897969802886507, 6620516959819538809, 17176182768010960895, 13503953896175478587, 4354685564936845355, 11912009170470909681, 8607219088846449759, 11170449401992604703, 16175846103906665108, 6620516959819538809], compress_intermediaries: None, final_v_xor: None},
                Mutation {v: [17350586023075716586, 7185456781098638035, 4354685564936845355, 11912009170470909681, 13249304492735193375, 17098411920136983822, 2270897969802886507, 6620516959819538809, 17176182768010960895, 8930117218777017854, 4354685564936845355, 11912009170470909681, 8607219088846449759, 2688359258937526054, 16175846103906665108, 6620516959819538809], compress_intermediaries: None, final_v_xor: None},
                Mutation {v: [17350586023075716586, 7185456781098638035, 13713719548237747159, 11912009170470909681, 13249304492735193375, 17098411920136983822, 11553535242626141553, 6620516959819538809, 17176182768010960895, 8930117218777017854, 12859234535676303609, 11912009170470909681, 8607219088846449759, 2688359258937526054, 8691176764166632836, 6620516959819538809], compress_intermediaries: None, final_v_xor: None},
                Mutation {v: [17350586023075716586, 7185456781098638035, 13713719548237747159, 10707313269246176532, 13249304492735193375, 17098411920136983822, 11553535242626141553, 8495551619518569222, 17176182768010960895, 8930117218777017854, 12859234535676303609, 12219501413424716073, 8607219088846449759, 2688359258937526054, 8691176764166632836, 11700058801282683630], compress_intermediaries: None, final_v_xor: None},
                Mutation {v: [9707440099081960313, 7185456781098638035, 13713719548237747159, 10707313269246176532, 13249304492735193375, 11837650394348604030, 11553535242626141553, 8495551619518569222, 17176182768010960895, 8930117218777017854, 18052591224639614398, 12219501413424716073, 8607219088846449759, 2688359258937526054, 8691176764166632836, 2528949647217589348], compress_intermediaries: None, final_v_xor: None},
                Mutation {v: [9707440099081960313, 13919708115642571251, 13713719548237747159, 10707313269246176532, 13249304492735193375, 11837650394348604030, 15999054287854434379, 8495551619518569222, 17176182768010960895, 8930117218777017854, 18052591224639614398, 5916165702131158410, 16153577839664528003, 2688359258937526054, 8691176764166632836, 2528949647217589348], compress_intermediaries: None, final_v_xor: None},
                Mutation {v: [9707440099081960313, 13919708115642571251, 14313883604204833422, 10707313269246176532, 13249304492735193375, 11837650394348604030, 15999054287854434379, 6439224605934397036, 13746022367454054535, 8930117218777017854, 18052591224639614398, 5916165702131158410, 16153577839664528003, 2052363037506523539, 8691176764166632836, 2528949647217589348], compress_intermediaries: None, final_v_xor: None},
                Mutation {v: [9707440099081960313, 13919708115642571251, 14313883604204833422, 902916003658517597, 4967013240145357303, 11837650394348604030, 15999054287854434379, 6439224605934397036, 13746022367454054535, 7090913738691013329, 18052591224639614398, 5916165702131158410, 16153577839664528003, 2052363037506523539, 10342616010177476862, 2528949647217589348], compress_intermediaries: None, final_v_xor: None},
                Mutation {v: [9707440099081960313, 13919708115642571251, 14313883604204833422, 902916003658517597, 4967013240145357303, 11837650394348604030, 15999054287854434379, 6439224605934397036, 13746022367454054535, 7090913738691013329, 18052591224639614398, 5916165702131158410, 16153577839664528003, 2052363037506523539, 10342616010177476862, 2528949647217589348], compress_intermediaries: None, final_v_xor: Some([4067999328311309310, 11766569583985701666, 4333185627401004848, 6817812180028899799, 11872448817906701172, 13275693745155513325, 5872787840850821301, 8810196352646273544])},
            ],
            read_records: vec![
                MemoryReadRecord { value: 16777216, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 33972 },
                MemoryReadRecord { value: 4072524104, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 34028 },
                MemoryReadRecord { value: 1779033703, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 34084 },
                MemoryReadRecord { value: 2227873595, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 34140 },
                MemoryReadRecord { value: 3144134277, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 34196 },
                MemoryReadRecord { value: 4271175723, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 34252 },
                MemoryReadRecord { value: 1013904242, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 34308 },
                MemoryReadRecord { value: 1595750129, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 34364 },
                MemoryReadRecord { value: 2773480762, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 34420 },
                MemoryReadRecord { value: 2917565137, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 34476 },
                MemoryReadRecord { value: 1359893119, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 34532 },
                MemoryReadRecord { value: 725511199, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 34588 },
                MemoryReadRecord { value: 2600822924, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 34644 },
                MemoryReadRecord { value: 4215389547, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 34700 },
                MemoryReadRecord { value: 528734635, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 34756 },
                MemoryReadRecord { value: 327033209, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 34812 },
                MemoryReadRecord { value: 1541459225, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 34868 },
                MemoryReadRecord { value: 6513249, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 34924 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 34980 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 35036 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 35092 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 35148 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 35204 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 35260 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 35316 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 35372 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 35428 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 35484 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 35540 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 35596 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 35652 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 35708 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 35764 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 35820 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 35876 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 35932 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 35988 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 36044 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 36100 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 36156 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 36212 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 36268 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 36324 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 36380 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 36436 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 36492 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 36548 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 36604 },
                MemoryReadRecord { value: 3, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 36716 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 36772 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 36828 },
                MemoryReadRecord { value: 0, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 36884 },
                MemoryReadRecord { value: 1, shard: 1, timestamp: 36932, prev_shard: 1, prev_timestamp: 36904 }
            ],
            write_records: vec![
                MemoryWriteRecord { value: 3057268748, shard: 1, timestamp: 36933, prev_value: 0, prev_shard: 0, prev_timestamp: 0 },
                MemoryWriteRecord { value: 2995354962, shard: 1, timestamp: 36933, prev_value: 0, prev_shard: 0, prev_timestamp: 0 },
                MemoryWriteRecord { value: 429172818, shard: 1, timestamp: 36933, prev_value: 0, prev_shard: 0, prev_timestamp: 0 },
                MemoryWriteRecord { value: 888024088, shard: 1, timestamp: 36933, prev_value: 0, prev_shard: 0, prev_timestamp: 0 },
                MemoryWriteRecord { value: 459244621, shard: 1, timestamp: 36933, prev_value: 0, prev_shard: 0, prev_timestamp: 0 },
                MemoryWriteRecord { value: 744639488, shard: 1, timestamp: 36933, prev_value: 0, prev_shard: 0, prev_timestamp: 0 },
                MemoryWriteRecord { value: 645392752, shard: 1, timestamp: 36933, prev_value: 0, prev_shard: 0, prev_timestamp: 0 },
                MemoryWriteRecord { value: 877253371, shard: 1, timestamp: 36933, prev_value: 0, prev_shard: 0, prev_timestamp: 0 },
                MemoryWriteRecord { value: 2773595048, shard: 1, timestamp: 36933, prev_value: 0, prev_shard: 1, prev_timestamp: 528 },
                MemoryWriteRecord { value: 859557365, shard: 1, timestamp: 36933, prev_value: 0, prev_shard: 1, prev_timestamp: 524 },
                MemoryWriteRecord { value: 4076331145, shard: 1, timestamp: 36933, prev_value: 0, prev_shard: 1, prev_timestamp: 520 },
                MemoryWriteRecord { value: 2480224547, shard: 1, timestamp: 36933, prev_value: 0, prev_shard: 1, prev_timestamp: 516 },
                MemoryWriteRecord { value: 3728565500, shard: 1, timestamp: 36933, prev_value: 0, prev_shard: 1, prev_timestamp: 512 },
                MemoryWriteRecord { value: 3331064654, shard: 1, timestamp: 36933, prev_value: 0, prev_shard: 1, prev_timestamp: 508 },
                MemoryWriteRecord { value: 1903923859, shard: 1, timestamp: 36933, prev_value: 0, prev_shard: 1, prev_timestamp: 504 },
                MemoryWriteRecord { value: 4275545121, shard: 1, timestamp: 36933, prev_value: 0, prev_shard: 1, prev_timestamp: 500 }
            ],
            local_mem_access: vec![
                MemoryLocalEvent { addr: 2097980, initial_mem_access: MemoryRecord { shard: 1, timestamp: 35652, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2098096, initial_mem_access: MemoryRecord { shard: 0, timestamp: 0, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36933, value: 744639488 } },
                MemoryLocalEvent { addr: 2097912, initial_mem_access: MemoryRecord { shard: 1, timestamp: 34700, value: 4215389547 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 4215389547 } },
                MemoryLocalEvent { addr: 2098032, initial_mem_access: MemoryRecord { shard: 1, timestamp: 36380, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2098068, initial_mem_access: MemoryRecord { shard: 1, timestamp: 36884, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2098040, initial_mem_access: MemoryRecord { shard: 1, timestamp: 36492, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2097916, initial_mem_access: MemoryRecord { shard: 1, timestamp: 34756, value: 528734635 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 528734635 } },
                MemoryLocalEvent { addr: 2098012, initial_mem_access: MemoryRecord { shard: 1, timestamp: 36100, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2098072, initial_mem_access: MemoryRecord { shard: 1, timestamp: 36904, value: 1 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 1 } },
                MemoryLocalEvent { addr: 2097944, initial_mem_access: MemoryRecord { shard: 1, timestamp: 35148, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2097880, initial_mem_access: MemoryRecord { shard: 1, timestamp: 34252, value: 4271175723 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 4271175723 } },
                MemoryLocalEvent { addr: 2098124, initial_mem_access: MemoryRecord { shard: 1, timestamp: 512, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36933, value: 3728565500 } },
                MemoryLocalEvent { addr: 2098100, initial_mem_access: MemoryRecord { shard: 0, timestamp: 0, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36933, value: 645392752 } },
                MemoryLocalEvent { addr: 2098020, initial_mem_access: MemoryRecord { shard: 1, timestamp: 36212, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2098060, initial_mem_access: MemoryRecord { shard: 1, timestamp: 36772, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2097984, initial_mem_access: MemoryRecord { shard: 1, timestamp: 35708, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2098064, initial_mem_access: MemoryRecord { shard: 1, timestamp: 36828, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2097920, initial_mem_access: MemoryRecord { shard: 1, timestamp: 34812, value: 327033209 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 327033209 } },
                MemoryLocalEvent { addr: 2098056, initial_mem_access: MemoryRecord { shard: 1, timestamp: 36716, value: 3 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 3 } },
                MemoryLocalEvent { addr: 2097928, initial_mem_access: MemoryRecord { shard: 1, timestamp: 34924, value: 6513249 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 6513249 } },
                MemoryLocalEvent { addr: 2098044, initial_mem_access: MemoryRecord { shard: 1, timestamp: 36548, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2098024, initial_mem_access: MemoryRecord { shard: 1, timestamp: 36268, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2097976, initial_mem_access: MemoryRecord { shard: 1, timestamp: 35596, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2097860, initial_mem_access: MemoryRecord { shard: 1, timestamp: 33972, value: 16777216 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 16777216 } },
                MemoryLocalEvent { addr: 2098004, initial_mem_access: MemoryRecord { shard: 1, timestamp: 35988, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2097924, initial_mem_access: MemoryRecord { shard: 1, timestamp: 34868, value: 1541459225 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 1541459225 } },
                MemoryLocalEvent { addr: 2097892, initial_mem_access: MemoryRecord { shard: 1, timestamp: 34420, value: 2773480762 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 2773480762 } },
                MemoryLocalEvent { addr: 2097968, initial_mem_access: MemoryRecord { shard: 1, timestamp: 35484, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2097956, initial_mem_access: MemoryRecord { shard: 1, timestamp: 35316, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2098084, initial_mem_access: MemoryRecord { shard: 0, timestamp: 0, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36933, value: 429172818 } },
                MemoryLocalEvent { addr: 2098116, initial_mem_access: MemoryRecord { shard: 1, timestamp: 520, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36933, value: 4076331145 } },
                MemoryLocalEvent { addr: 2098120, initial_mem_access: MemoryRecord { shard: 1, timestamp: 516, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36933, value: 2480224547 } },
                MemoryLocalEvent { addr: 2097868, initial_mem_access: MemoryRecord { shard: 1, timestamp: 34084, value: 1779033703 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 1779033703 } },
                MemoryLocalEvent { addr: 2098104, initial_mem_access: MemoryRecord { shard: 0, timestamp: 0, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36933, value: 877253371 } },
                MemoryLocalEvent { addr: 2098136, initial_mem_access: MemoryRecord { shard: 1, timestamp: 500, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36933, value: 4275545121 } },
                MemoryLocalEvent { addr: 2097864, initial_mem_access: MemoryRecord { shard: 1, timestamp: 34028, value: 4072524104 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 4072524104 } },
                MemoryLocalEvent { addr: 2097996, initial_mem_access: MemoryRecord { shard: 1, timestamp: 35876, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2097972, initial_mem_access: MemoryRecord { shard: 1, timestamp: 35540, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2097964, initial_mem_access: MemoryRecord { shard: 1, timestamp: 35428, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2097888, initial_mem_access: MemoryRecord { shard: 1, timestamp: 34364, value: 1595750129 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 1595750129 } },
                MemoryLocalEvent { addr: 2097992, initial_mem_access: MemoryRecord { shard: 1, timestamp: 35820, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2098128, initial_mem_access: MemoryRecord { shard: 1, timestamp: 508, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36933, value: 3331064654 } },
                MemoryLocalEvent { addr: 2098016, initial_mem_access: MemoryRecord { shard: 1, timestamp: 36156, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2098132, initial_mem_access: MemoryRecord { shard: 1, timestamp: 504, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36933, value: 1903923859 } },
                MemoryLocalEvent { addr: 2098036, initial_mem_access: MemoryRecord { shard: 1, timestamp: 36436, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2098080, initial_mem_access: MemoryRecord { shard: 0, timestamp: 0, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36933, value: 2995354962 } },
                MemoryLocalEvent { addr: 2098000, initial_mem_access: MemoryRecord { shard: 1, timestamp: 35932, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2098088, initial_mem_access: MemoryRecord { shard: 0, timestamp: 0, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36933, value: 888024088 } },
                MemoryLocalEvent { addr: 2098052, initial_mem_access: MemoryRecord { shard: 1, timestamp: 36660, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2098008, initial_mem_access: MemoryRecord { shard: 1, timestamp: 36044, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2097908, initial_mem_access: MemoryRecord { shard: 1, timestamp: 34644, value: 2600822924 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 2600822924 } },
                MemoryLocalEvent { addr: 2097936, initial_mem_access: MemoryRecord { shard: 1, timestamp: 35036, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2097988, initial_mem_access: MemoryRecord { shard: 1, timestamp: 35764, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2098028, initial_mem_access: MemoryRecord { shard: 1, timestamp: 36324, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2097932, initial_mem_access: MemoryRecord { shard: 1, timestamp: 34980, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2098076, initial_mem_access: MemoryRecord { shard: 0, timestamp: 0, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36933, value: 3057268748 } },
                MemoryLocalEvent { addr: 2097900, initial_mem_access: MemoryRecord { shard: 1, timestamp: 34532, value: 1359893119 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 1359893119 } },
                MemoryLocalEvent { addr: 2098048, initial_mem_access: MemoryRecord { shard: 1, timestamp: 36604, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2097876, initial_mem_access: MemoryRecord { shard: 1, timestamp: 34196, value: 3144134277 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 3144134277 } },
                MemoryLocalEvent { addr: 2098092, initial_mem_access: MemoryRecord { shard: 0, timestamp: 0, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36933, value: 459244621 } },
                MemoryLocalEvent { addr: 2098112, initial_mem_access: MemoryRecord { shard: 1, timestamp: 524, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36933, value: 859557365 } },
                MemoryLocalEvent { addr: 2097904, initial_mem_access: MemoryRecord { shard: 1, timestamp: 34588, value: 725511199 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 725511199 } },
                MemoryLocalEvent { addr: 2097896, initial_mem_access: MemoryRecord { shard: 1, timestamp: 34476, value: 2917565137 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 2917565137 } },
                MemoryLocalEvent { addr: 2098108, initial_mem_access: MemoryRecord { shard: 1, timestamp: 528, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36933, value: 2773595048 } },
                MemoryLocalEvent { addr: 2097884, initial_mem_access: MemoryRecord { shard: 1, timestamp: 34308, value: 1013904242 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 1013904242 } },
                MemoryLocalEvent { addr: 2097948, initial_mem_access: MemoryRecord { shard: 1, timestamp: 35204, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2097872, initial_mem_access: MemoryRecord { shard: 1, timestamp: 34140, value: 2227873595 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 2227873595 } },
                MemoryLocalEvent { addr: 2097960, initial_mem_access: MemoryRecord { shard: 1, timestamp: 35372, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2097940, initial_mem_access: MemoryRecord { shard: 1, timestamp: 35092, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } },
                MemoryLocalEvent { addr: 2097952, initial_mem_access: MemoryRecord { shard: 1, timestamp: 35260, value: 0 }, final_mem_access: MemoryRecord { shard: 1, timestamp: 36932, value: 0 } }
            ]
        };

        let syscall_event = SyscallEvent {
            pc: 2102156,
            next_pc: 2102160,
            shard: 1,
            clk: 36932,
            a_record: MemoryWriteRecord::default(),
            a_record_is_real: false,
            op_a_0: false,
            syscall_code: SyscallCode::BLAKE2F_COMPRESS,
            syscall_id: SyscallCode::BLAKE2F_COMPRESS.syscall_id(),
            arg1: 2097860,
            arg2: 0,
        };
        /*
        let third_syscall_event = SyscallEvent {
            pc: 2102156,
            next_pc: 2102160,
            shard: 1,
            clk: 36932,
            a_record: MemoryWriteRecord { value: 65840, shard: 1, timestamp: 36935, prev_value: 65840, prev_shard: 1, prev_timestamp: 36927 },
            a_record_is_real: false,
            op_a_0: false,
            syscall_code: SyscallCode::BLAKE2F_COMPRESS,
            syscall_id: SyscallCode::BLAKE2F_COMPRESS.syscall_id(),
            arg1: 2097860,
            arg2: 0,
        };
         */

        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let mut shard = ExecutionRecord::default();
        
        shard.precompile_events.add_event(SyscallCode::BLAKE2F_COMPRESS, syscall_event, sp1_core_executor::events::PrecompileEvent::Blake2fCompress(event.clone()));
        // shard.precompile_events.add_event(SyscallCode::BLAKE2F_COMPRESS, syscall_event, sp1_core_executor::events::PrecompileEvent::Blake2fCompress(event.clone()));
        //shard.precompile_events.add_event(SyscallCode::BLAKE2F_COMPRESS, third_syscall_event, sp1_core_executor::events::PrecompileEvent::Blake2fCompress(event.clone()));

        let chip = Blake2fCompressChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();

        // Add assertions to verify the event data
        assert_eq!(event.shard, 1);
    }
}