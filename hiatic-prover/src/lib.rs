use std::{
    fs,
    path::{Path, PathBuf},
    rc::Rc,
};

use anyhow::{Context, bail, ensure};
use cairo_air::utils::ProofFormat;
use cairo_lang_compiler::{
    db::RootDatabase, diagnostics::DiagnosticsReporter, project::setup_project,
};
use cairo_lang_executable::{
    compile::{ExecutableConfig, compile_executable_in_prepared_db},
    executable::{EntryPointKind, Executable},
};
use cairo_lang_executable_plugin::executable_plugin_suite;
use cairo_lang_execute_utils::program_and_hints_from_executable;
use cairo_lang_filesystem::{
    cfg::{Cfg, CfgSet},
    db::init_dev_corelib,
    ids::CrateInput,
};
use cairo_program_runner_lib::{
    PRIVACY_SIMPLE_BOOTLOADER_COMPILED_JSON, ProgramInput, SimpleBootloaderInput, Task, TaskSpec,
    cairo_run_program,
    hints::types::{Cairo1Executable, HashFunc, PrivacySimpleBootloaderInput},
};
use cairo_vm::{
    Felt252,
    cairo_run::CairoRunConfig,
    types::{layout_name::LayoutName, program::Program},
};
use serde_json::Value;
use stwo_cairo_adapter::{ProverInput, adapter::adapt};
use stwo_cairo_prover::prover::create_and_serialize_proof;

use hiatic_proofs::{Candidate, VerifiedOutput, inspect_candidate};

pub struct ProvingOutput {
    pub candidate: Candidate,
    pub verified_output: VerifiedOutput,
}

pub fn compile_cairo_project(
    project_dir: &Path,
    source_file: &Path,
    entrypoint: &str,
    corelib_dir: &Path,
) -> anyhow::Result<Executable> {
    ensure!(
        is_identifier(entrypoint),
        "invalid Cairo entrypoint: {entrypoint}"
    );

    let project_dir = project_dir
        .canonicalize()
        .with_context(|| format!("resolving project {}", project_dir.display()))?;
    let source_file = project_dir
        .join(source_file)
        .canonicalize()
        .with_context(|| format!("resolving entrypoint source {}", source_file.display()))?;
    let source_relative = source_file
        .strip_prefix(&project_dir)
        .context("entrypoint source must be inside the Cairo project")?;
    ensure!(
        project_dir.join("cairo_project.toml").is_file(),
        "project must contain cairo_project.toml"
    );

    let temporary_project = tempfile::tempdir().context("creating temporary Cairo project")?;
    copy_project(&project_dir, temporary_project.path())?;
    let temporary_source = temporary_project.path().join(source_relative);
    mark_executable(&temporary_source, entrypoint)?;

    let corelib_dir = corelib_dir
        .canonicalize()
        .with_context(|| format!("resolving Cairo corelib {}", corelib_dir.display()))?;
    ensure!(
        corelib_dir.join("lib.cairo").is_file(),
        "Cairo corelib path must point to its src directory: {}",
        corelib_dir.display()
    );

    let mut db = RootDatabase::builder()
        .skip_auto_withdraw_gas()
        .with_cfg(CfgSet::from_iter([Cfg::kv("gas", "disabled")]))
        .with_default_plugin_suite(executable_plugin_suite())
        .build()
        .context("creating Cairo compiler database")?;
    init_dev_corelib(&mut db, corelib_dir);

    let crate_inputs =
        setup_project(&mut db, temporary_project.path()).context("loading Cairo project")?;
    let crate_ids = CrateInput::into_crate_ids(&db, crate_inputs.clone());
    ensure!(!crate_ids.is_empty(), "Cairo project has no crate root");
    let compiled = compile_executable_in_prepared_db(
        &db,
        None,
        crate_ids,
        DiagnosticsReporter::stderr().with_crates(&crate_inputs),
        ExecutableConfig::default(),
    )
    .with_context(|| format!("compiling Cairo entrypoint {entrypoint}"))?;

    Ok(Executable::new(compiled.compiled_function))
}

pub fn run_cairo1(executable: &Executable, input: &[String]) -> anyhow::Result<ProverInput> {
    let entrypoint = executable
        .entrypoints
        .iter()
        .find(|entrypoint| matches!(entrypoint.kind, EntryPointKind::Bootloader))
        .context("Cairo executable has no bootloader entrypoint")?;
    let (program, string_to_hint) = program_and_hints_from_executable(executable, entrypoint)
        .context("loading Cairo executable for Cairo VM")?;

    let mut input_values = Vec::with_capacity(input.len());
    for (index, value) in input.iter().enumerate() {
        Felt252::from_dec_str(value)
            .with_context(|| format!("input argument {index} is not a valid felt252"))?;
        input_values.push(
            value
                .parse()
                .with_context(|| format!("input argument {index} is not a decimal integer"))?,
        );
    }

    let user_args = cairo_lang_execute_utils::user_args_from_flags(None, &input_values)
        .context("converting input values to Cairo arguments")?;
    let task = Task::Cairo1Program(Cairo1Executable {
        program,
        user_args,
        string_to_hint,
    });
    let task_spec = TaskSpec {
        task: Rc::new(task),
        program_hash_function: HashFunc::Poseidon,
    };
    let bootloader = Program::from_bytes(PRIVACY_SIMPLE_BOOTLOADER_COMPILED_JSON, Some("main"))
        .context("loading Stwo privacy simple bootloader")?;
    let output_dir = tempfile::tempdir().context("creating execution temporary directory")?;
    let bootloader_input = PrivacySimpleBootloaderInput {
        simple_bootloader_input: SimpleBootloaderInput {
            fact_topologies_path: None,
            single_page: true,
            tasks: vec![task_spec],
        },
        output_preimage_dump_path: output_dir.path().join("preimages.json"),
    };
    let config = CairoRunConfig {
        entrypoint: "main",
        trace_enabled: true,
        relocate_mem: false,
        relocate_trace: false,
        layout: LayoutName::all_cairo_stwo,
        proof_mode: true,
        fill_holes: true,
        secure_run: None,
        disable_trace_padding: true,
        allow_missing_builtins: None,
        dynamic_layout_params: None,
    };

    let runner = cairo_run_program(
        &bootloader,
        Some(ProgramInput::Value(Box::new(bootloader_input))),
        config,
        None,
    )
    .context("executing Cairo program in proof mode")?;

    adapt(&runner).context("adapting Cairo execution for Stwo")
}

pub fn prove_cairo_project(
    project_dir: &Path,
    source_file: &Path,
    entrypoint: &str,
    corelib_dir: &Path,
    input: &[String],
    proof_path: &Path,
    prover_parameters: Option<PathBuf>,
) -> anyhow::Result<ProvingOutput> {
    let executable = compile_cairo_project(project_dir, source_file, entrypoint, corelib_dir)?;
    let prover_input = run_cairo1(&executable, input)?;
    create_and_serialize_proof(
        prover_input,
        false,
        proof_path.to_path_buf(),
        ProofFormat::Binary,
        prover_parameters,
    )
    .context("creating Stwo Cairo proof")?;

    let proof_bytes =
        fs::read(proof_path).with_context(|| format!("reading proof {}", proof_path.display()))?;
    let candidate = Candidate::from_proof_bytes(&proof_bytes);
    let verified_output = inspect_candidate(&candidate).map_err(anyhow::Error::msg)?;
    Ok(ProvingOutput {
        candidate,
        verified_output,
    })
}

fn copy_project(source: &Path, destination: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(destination)
        .with_context(|| format!("creating temporary directory {}", destination.display()))?;
    for entry in fs::read_dir(source)
        .with_context(|| format!("reading Cairo project {}", source.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        if name == ".git" || name == "target" {
            continue;
        }
        let source_path = entry.path();
        let destination_path = destination.join(&name);
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_project(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path)
                .with_context(|| format!("copying Cairo project file {}", source_path.display()))?;
        } else {
            bail!(
                "unsupported filesystem entry in Cairo project: {}",
                source_path.display()
            );
        }
    }
    Ok(())
}

fn mark_executable(source_path: &Path, entrypoint: &str) -> anyhow::Result<()> {
    let source = fs::read_to_string(source_path)
        .with_context(|| format!("reading Cairo source {}", source_path.display()))?;
    let declaration = format!("pub fn {entrypoint}(");
    ensure!(
        source.matches(&declaration).count() == 1,
        "expected one `pub fn {entrypoint}(...)` in {}",
        source_path.display()
    );
    if source.contains(&format!("#[executable]\n{declaration}")) {
        return Ok(());
    }
    let executable_declaration = format!("#[executable]\n{declaration}");
    let source = source.replacen(&declaration, &executable_declaration, 1);
    fs::write(source_path, source).with_context(|| format!("marking {entrypoint} executable"))
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(first) if first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

pub fn read_input_json(path: &Path) -> anyhow::Result<Vec<String>> {
    let input: Value = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("parsing {}", path.display()))?;
    let values = input
        .as_array()
        .context("Cairo input must be a JSON array of decimal felt strings")?;
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .as_str()
                .map(str::to_owned)
                .with_context(|| format!("Cairo input item {index} must be a string"))
        })
        .collect()
}
