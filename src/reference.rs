use {
    crate::args::ClapArgumentLoader,
    anyhow::{
        Context,
        Result,
    },
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
        clap_complete::generate_to(*shell, &mut app, env!("CARGO_PKG_NAME"), outdir)
            .with_context(|| format!("Failed to write shell completion in {}", outdir.display()))?;
        Ok(())
    }

    pub(crate) fn build_markdown(&self, outdir: &Path) -> Result<()> {
        for (name, command) in self.collect_commands() {
            let path = outdir.join(format!("{}.md", name.trim_start_matches('-')));
            let mut file = File::create(&path).with_context(|| format!("Failed to create {}", path.display()))?;
            file.write_all(clap_markdown::help_markdown_command(&command).as_bytes())
                .with_context(|| format!("Failed to write {}", path.display()))?;
        }
        Ok(())
    }

    pub(crate) fn build_manpages(&self, outdir: &Path) -> Result<()> {
        for (name, command) in self.collect_commands() {
            let path = outdir.join(format!("{}.1", name.trim_start_matches('-')));
            let mut file = File::create(&path).with_context(|| format!("Failed to create {}", path.display()))?;
            Man::new(command)
                .render(&mut file)
                .with_context(|| format!("Failed to write {}", path.display()))?;
        }
        Ok(())
    }

    fn collect_commands(&self) -> Vec<(String, clap::Command)> {
        let mut commands = Vec::new();
        fn walk(path: &str, commands: &mut Vec<(String, clap::Command)>, parent: &clap::Command) {
            let new_path = format!("{path}-{}", parent.get_name());
            commands.push((new_path.clone(), parent.clone()));
            for subcommand in parent.get_subcommands() {
                walk(&new_path, commands, subcommand);
            }
        }
        walk("", &mut commands, &ClapArgumentLoader::root_command());
        commands
    }
}
