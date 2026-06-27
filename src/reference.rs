use {
    crate::args::ClapArgumentLoader,
    anyhow::Result,
    clap_complete::Shell,
    clap_mangen::Man,
    std::{
        fs::File,
        io::Write,
        path::Path,
    },
};

/// Generates manpages, markdown docs, and shell completions from the CLI
/// definition.
pub(crate) struct ReferenceBuilder;

impl ReferenceBuilder {
    pub(crate) fn new() -> Self {
        Self
    }

    pub(crate) fn build_shell_completion(&self, outdir: &Path, shell: &Shell) -> Result<()> {
        let mut app = ClapArgumentLoader::root_command();
        clap_complete::generate_to(*shell, &mut app, env!("CARGO_PKG_NAME"), outdir)?;
        Ok(())
    }

    pub(crate) fn build_markdown(&self, outdir: &Path) -> Result<()> {
        for cmd in self.collect_commands() {
            let file = outdir.join(format!("{}.md", cmd.0.trim_start_matches('-')));
            let mut file = File::create(&file)?;
            file.write_all(clap_markdown::help_markdown_command(&cmd.1).as_bytes())?;
        }
        Ok(())
    }

    pub(crate) fn build_manpages(&self, outdir: &Path) -> Result<()> {
        for cmd in self.collect_commands() {
            let file = outdir.join(format!("{}.1", cmd.0.trim_start_matches('-')));
            let mut file = File::create(&file)?;
            Man::new(cmd.1).render(&mut file)?;
        }

        Ok(())
    }

    fn collect_commands(&self) -> Vec<(String, clap::Command)> {
        let mut cmds: Vec<(String, clap::Command)> = Vec::new();
        fn rec_add(path: &str, cmds: &mut Vec<(String, clap::Command)>, parent: &clap::Command) {
            let new_path = &format!("{}-{}", path, parent.get_name());
            cmds.push((new_path.into(), parent.clone()));
            for subc in parent.get_subcommands() {
                rec_add(new_path, cmds, subc);
            }
        }
        rec_add("", &mut cmds, &ClapArgumentLoader::root_command());
        cmds
    }
}
