//! GRUB script as check reads it: the commands a script file runs when GRUB
//! executes it, and the variables each can set. GRUB's lexer splits a line
//! into words and commands (grub-core/script/yylex.l), its parser groups
//! them into compound commands and bodies (grub-core/script/parser.y), and
//! a command sets a variable only by assigning it: set, unset, NAME=VALUE,
//! or a command that takes the variable's name as an argument. check reads
//! the words and keywords Fedora's generated files use, and reports a line
//! it cannot split instead of guessing what it does.

use std::collections::HashMap;

/// A word of a command, its quotes and escapes removed.
#[derive(Debug, Clone, PartialEq)]
pub struct Word {
    pub text: String,
    /// Byte offset in text of the first variable the word expands. text
    /// keeps each expansion as written.
    pub expansion: Option<usize>,
    /// The word as its text and the variables it expands, in order.
    pub parts: Vec<Part>,
}

/// A part of a word: text, or a variable GRUB expands there, inside double
/// quotes or not. GRUB splits an unquoted expansion's value into words and
/// drops an empty one (grub-core/script/argv.c).
#[derive(Debug, Clone, PartialEq)]
pub enum Part {
    Text(String),
    Variable { name: String, quoted: bool },
}

impl Word {
    fn literal(text: &str) -> Self {
        Word { text: text.to_string(), expansion: None, parts: vec![Part::Text(text.to_string())] }
    }

    fn push(&mut self, c: char) {
        self.text.push(c);
        match self.parts.last_mut() {
            Some(Part::Text(text)) => text.push(c),
            _ => self.parts.push(Part::Text(c.to_string())),
        }
    }

    /// Whether the word is exactly text, with nothing expanded.
    pub fn is(&self, text: &str) -> bool {
        self.expansion.is_none() && self.text == text
    }
}

/// The characters GRUB's lexer reads as operators, which Fedora's
/// generated files do not use (yylex.l: "||", "&&", "|", "&", "<", ">").
const OPERATORS: [char; 4] = ['|', '&', '<', '>'];

/// The commands of one line, each as its words: GRUB's lexer separates
/// words at blanks and commands at ';', reads '{' and '}' as words of
/// their own, removes quotes, and reads '#' at the start of a word as a
/// comment to the end of the line (yylex.l). A quote left open, a
/// backslash at the end of the line, or an operator stops the split.
fn split(line: &str) -> Result<Vec<Vec<Word>>, &'static str> {
    let mut commands = Vec::new();
    let mut words: Vec<Word> = Vec::new();
    let mut word: Option<Word> = None;
    let mut chars = line.chars().peekable();

    fn finish(word: &mut Option<Word>, words: &mut Vec<Word>) {
        if let Some(w) = word.take() {
            words.push(w);
        }
    }
    fn expansion(word: &mut Option<Word>) -> &mut Word {
        word.get_or_insert_with(|| Word { text: String::new(), expansion: None, parts: Vec::new() })
    }

    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => finish(&mut word, &mut words),
            '#' if word.is_none() => break,
            ';' => {
                finish(&mut word, &mut words);
                if !words.is_empty() {
                    commands.push(std::mem::take(&mut words));
                }
            }
            '{' | '}' => {
                finish(&mut word, &mut words);
                words.push(Word::literal(&c.to_string()));
            }
            c if OPERATORS.contains(&c) => return Err("it uses an operator GRUB's generated files do not use"),
            '\'' => {
                let w = expansion(&mut word);
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(q) => w.push(q),
                        None => return Err("a quote continues on the next line"),
                    }
                }
            }
            '"' => {
                let w = expansion(&mut word);
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(e) => w.push(e),
                            None => return Err("a quote continues on the next line"),
                        },
                        Some('$') => read_variable(w, &mut chars, true)?,
                        Some(q) => w.push(q),
                        None => return Err("a quote continues on the next line"),
                    }
                }
            }
            '\\' => match chars.next() {
                Some(e) => expansion(&mut word).push(e),
                None => return Err("the line continues on the next one"),
            },
            '$' => read_variable(expansion(&mut word), &mut chars, false)?,
            c => expansion(&mut word).push(c),
        }
    }
    finish(&mut word, &mut words);
    if !words.is_empty() {
        commands.push(words);
    }
    Ok(commands)
}

/// Reads the variable a '$' expands into w, as written: $NAME, ${NAME},
/// $DIGITS or a special parameter (yylex.l, VARIABLE). quoted says whether
/// it stands inside double quotes.
fn read_variable(w: &mut Word, chars: &mut std::iter::Peekable<std::str::Chars>, quoted: bool) -> Result<(), &'static str> {
    w.expansion.get_or_insert(w.text.len());
    w.text.push('$');
    let mut name = String::new();
    if chars.peek() == Some(&'{') {
        w.text.push('{');
        chars.next();
        loop {
            match chars.next() {
                Some('}') => break,
                Some(c) => name.push(c),
                None => return Err("a variable's braces are not closed"),
            }
        }
        w.text.push_str(&name);
        w.text.push('}');
    } else {
        while let Some(&c) = chars.peek() {
            let special = name.is_empty() && matches!(c, '?' | '#' | '*' | '@');
            if !(c.is_ascii_alphanumeric() || c == '_' || special) {
                break;
            }
            name.push(c);
            chars.next();
            if special {
                break;
            }
        }
        if name.is_empty() {
            return Err("a '$' expands no variable");
        }
        w.text.push_str(&name);
    }
    w.parts.push(Part::Variable { name, quoted });
    Ok(())
}

/// What a command can set.
#[derive(Debug, PartialEq)]
pub enum Sets {
    /// These variables, named in the command.
    Names(Vec<String>),
    /// Any variable: its name is the value of a variable, or the command
    /// runs script that check does not read.
    Any,
}

/// Commands that read script from a file or a string and run it, setting
/// any variable it sets (commands/configfile.c, eval.c, loadenv.c,
/// legacycfg.c, efi/env.c, normal/main.c).
pub const LOADING_COMMANDS: [&str; 13] = [
    "source", ".", "configfile", "load_env", "eval", "normal",
    "extract_entries_source", "extract_entries_configfile",
    "extract_legacy_entries_source", "extract_legacy_entries_configfile",
    "legacy_source", "legacy_configfile", "efi-load-env",
];

/// Commands that set no variable, whatever their arguments name: tests,
/// output, exporting or saving variables, loading modules, checking a
/// password, loading a font or a background image, and choosing a terminal
/// (commands/test.c, echo.c, loadenv.c, password_pbkdf2.c, terminal.c;
/// kern/corecmd.c, insmod; normal/main.c, export; font/font_cmd.c;
/// term/gfxterm_background.c).
const SETS_NOTHING: [&str; 11] = [
    "[", "test", "echo", "export", "save_env", "insmod", "password_pbkdf2",
    "loadfont", "background_image", "terminal_input", "terminal_output",
];

/// Keywords that begin a compound command or one of its parts, after which
/// the next words form a command (parser.y).
const LEADING_KEYWORDS: [&str; 8] = ["if", "elif", "then", "else", "while", "until", "do", "!"];

/// What the simple command words can set. set assigns its first argument
/// up to '=' (kern/corecmd.c, grub_core_cmd_set), unset its first argument
/// (grub_core_cmd_unset), and a command name holding '=' is an assignment
/// (script/execute.c, grub_script_execute_cmdline). Another command can set
/// a variable whose name it is given, as search --set=NAME, read NAME or
/// regexp --set=NAME do, so every name in its arguments counts, and an
/// argument holding an expansion may name any variable. search with --set
/// and no name sets root (commands/search_wrap.c).
pub fn sets(words: &[Word]) -> Sets {
    let Some(command) = words.first() else {
        return Sets::Names(Vec::new());
    };
    if command.expansion.is_some() && !assignment_name_is_literal(command) {
        return Sets::Any;
    }
    if command.text.contains('=') {
        return Sets::Names(vec![command.text[..command.text.find('=').unwrap_or(0)].to_string()]);
    }
    let arguments = &words[1..];
    match command.text.as_str() {
        "set" => match arguments.first() {
            Some(argument) if !assignment_name_is_literal(argument) => Sets::Any,
            Some(argument) => Sets::Names(argument.text.find('=')
                .map(|eq| vec![argument.text[..eq].to_string()]).unwrap_or_default()),
            None => Sets::Names(Vec::new()),
        },
        "unset" => match arguments.first() {
            Some(argument) if argument.expansion.is_some() => Sets::Any,
            Some(argument) => Sets::Names(vec![argument.text.clone()]),
            None => Sets::Names(Vec::new()),
        },
        name if LOADING_COMMANDS.contains(&name) => Sets::Any,
        name if SETS_NOTHING.contains(&name) => Sets::Names(Vec::new()),
        "menuentry" | "submenu" | "function" => Sets::Names(Vec::new()),
        name => {
            if arguments.iter().any(|a| a.expansion.is_some()) {
                return Sets::Any;
            }
            let mut names: Vec<String> = arguments.iter()
                .flat_map(|a| a.text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')))
                .filter(|n| !n.is_empty())
                .map(str::to_string)
                .collect();
            if name == "search" && arguments.iter().any(|a| sets_root_by_default(&a.text)) {
                names.push("root".to_string());
            }
            Sets::Names(names)
        }
    }
}

/// Whether a set argument or a command name names its variable without an
/// expansion: no expansion before the first '=', and an '=' after a
/// variable's value could not supply one.
fn assignment_name_is_literal(word: &Word) -> bool {
    match (word.expansion, word.text.find('=')) {
        (None, _) => true,
        (Some(at), Some(eq)) => eq < at,
        (Some(_), None) => false,
    }
}

/// Whether a search argument is its --set option without a variable name,
/// alone or among short options, which sets root (search_wrap.c).
fn sets_root_by_default(argument: &str) -> bool {
    argument == "--set" || (argument.starts_with('-') && !argument.starts_with("--") && argument.contains('s'))
}

/// Whether a command runs where a script stands.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Runs {
    Yes,
    No,
    /// It runs or not as something check cannot evaluate decides.
    Maybe,
}

impl Runs {
    fn and(self, other: Runs) -> Runs {
        match (self, other) {
            (Runs::No, _) | (_, Runs::No) => Runs::No,
            (Runs::Yes, other) | (other, Runs::Yes) => other,
            _ => Runs::Maybe,
        }
    }

    fn not(self) -> Runs {
        match self {
            Runs::Yes => Runs::No,
            Runs::No => Runs::Yes,
            Runs::Maybe => Runs::Maybe,
        }
    }

    /// A command's exit status, success or failure, or None when unknown.
    fn of(status: Option<bool>) -> Runs {
        match status {
            Some(true) => Runs::Yes,
            Some(false) => Runs::No,
            None => Runs::Maybe,
        }
    }
}

/// One command a script runs where it stands: not in the body of a menu
/// entry or function, which runs only when booted or called, nor in a branch
/// GRUB does not take. A call of a function the script defined runs the
/// commands of its body.
#[derive(Debug)]
pub struct Command {
    /// The line the command is on, as the script holds it.
    pub line: String,
    /// The command's words, without the keywords that lead into it.
    pub words: Vec<Word>,
    /// Whether it runs inside a branch or loop whose running check cannot
    /// evaluate, so it may not run.
    pub conditional: bool,
    /// Whether it runs inside a while, until or for, so it may run more
    /// than once.
    pub in_loop: bool,
}

/// What runs the commands a Reader reads: each command where the script
/// stands, and the exit status of a condition, which decides the branch.
pub trait Runner {
    type Error;
    /// Runs command.
    fn run(&mut self, command: &Command) -> Result<(), Self::Error>;
    /// Whether command, which has just run, succeeded; None when the runner
    /// cannot tell.
    fn succeeded(&mut self, command: &Command) -> Result<Option<bool>, Self::Error>;
    /// The error for line, which check cannot read, and why.
    fn unreadable(&self, line: &str, why: &str) -> Self::Error;
}

/// A body that has opened and not closed: a function's, recorded for its
/// calls, or a menu entry's.
struct Body {
    function: Option<String>,
    /// Bodies opened inside this one and not closed.
    nested: usize,
}

/// A function's body as the script defines it: its commands with their
/// lines, or None when it defines a menu entry or function of its own,
/// which check does not follow into a call.
type FunctionBody = Option<Vec<(String, Vec<Word>)>>;

/// A compound command a script is inside where it stands (parser.y).
enum Frame {
    /// An if: whether GRUB reaches the next condition or else without having
    /// taken a branch, whether the current branch runs, and, while a
    /// condition is being read, its exit status so far.
    If { untaken: Runs, branch: Runs, condition: Option<Option<bool>> },
    /// A while, until or for, whose body runs any number of times.
    Loop { body: Runs },
}

/// Reads a script line by line as GRUB runs it from top to bottom.
#[derive(Default)]
pub struct Reader {
    bodies: Vec<Body>,
    functions: HashMap<String, FunctionBody>,
    /// The functions being called, innermost last.
    calling: Vec<String>,
    /// The compound commands open where the script stands, innermost last.
    frames: Vec<Frame>,
    /// Whether a '!' inverts the next condition's status.
    invert: bool,
}

impl Reader {
    /// Whether the next line is in the body of a menu entry or function.
    pub fn in_body(&self) -> bool {
        !self.bodies.is_empty()
    }

    /// Whether a command where the script stands runs.
    pub fn runs(&self) -> Runs {
        match self.frames.last() {
            None => Runs::Yes,
            Some(Frame::If { untaken, condition: Some(_), .. }) => *untaken,
            Some(Frame::If { branch, .. }) => *branch,
            Some(Frame::Loop { body }) => *body,
        }
    }

    fn in_loop(&self) -> bool {
        self.frames.iter().any(|frame| matches!(frame, Frame::Loop { .. }))
    }

    /// Reads line and runs its commands with runner, in order.
    pub fn line<R: Runner>(&mut self, line: &str, runner: &mut R) -> Result<(), R::Error> {
        for words in split(line).map_err(|why| runner.unreadable(line, why))? {
            self.command(line, words, runner)?;
        }
        Ok(())
    }

    fn command<R: Runner>(&mut self, line: &str, mut words: Vec<Word>, runner: &mut R) -> Result<(), R::Error> {
        let unreadable = |runner: &R, why: &str| runner.unreadable(line, why);
        if let Some(body) = self.bodies.last_mut() {
            if words.first().is_some_and(|w| w.is("}")) {
                if words.len() > 1 {
                    return Err(unreadable(runner, "words follow the '}' that closes a body"));
                }
                if body.nested > 0 {
                    body.nested -= 1;
                } else {
                    self.bodies.pop();
                }
                return Ok(());
            }
            let opens = words.iter().any(|w| w.is("{"));
            if body.nested == 0 && let Some(function) = &body.function {
                match self.functions.get_mut(function) {
                    Some(Some(commands)) if !opens => commands.push((line.to_string(), words)),
                    Some(recorded) => *recorded = None,
                    None => {}
                }
            }
            if opens {
                body.nested += 1;
            }
            return Ok(());
        }

        while let Some(keyword) = words.first().filter(|w| LEADING_KEYWORDS.iter().any(|k| w.is(k))) {
            let keyword = keyword.text.clone();
            words.remove(0);
            match keyword.as_str() {
                "if" => {
                    let untaken = self.runs();
                    self.frames.push(Frame::If { untaken, branch: Runs::No, condition: Some(None) });
                }
                "elif" => match self.frames.last_mut() {
                    Some(Frame::If { condition: condition @ None, .. }) => *condition = Some(None),
                    _ => return Err(unreadable(runner, "its elif follows no branch of an if")),
                },
                "then" => match self.frames.last_mut() {
                    Some(Frame::If { untaken, branch, condition }) if condition.is_some() => {
                        let holds = Runs::of(condition.unwrap_or(None));
                        *branch = untaken.and(holds);
                        *untaken = untaken.and(holds.not());
                        *condition = None;
                    }
                    _ => return Err(unreadable(runner, "its then follows no condition of an if")),
                },
                "else" => match self.frames.last_mut() {
                    Some(Frame::If { untaken, branch, condition: None }) => *branch = *untaken,
                    _ => return Err(unreadable(runner, "its else follows no branch of an if")),
                },
                "while" | "until" => {
                    let body = self.runs().and(Runs::Maybe);
                    self.frames.push(Frame::Loop { body });
                }
                "!" => self.invert = !self.invert,
                _ => {}
            }
        }
        let Some(first) = words.first() else {
            return Ok(());
        };
        if first.is("fi") || first.is("done") {
            let closes = match self.frames.last() {
                Some(Frame::If { condition: None, .. }) => first.is("fi"),
                Some(Frame::Loop { .. }) => first.is("done"),
                _ => false,
            };
            if words.len() > 1 || !closes {
                return Err(unreadable(runner, &format!("its {} closes no compound command it opened", first.text)));
            }
            self.frames.pop();
            return Ok(());
        }
        if first.is("{") || first.is("}") {
            return Err(unreadable(runner, "a brace stands outside the body of a menu entry or function"));
        }
        if ["case", "esac", "select", "[["].iter().any(|k| first.is(k)) {
            return Err(unreadable(runner, &format!("it uses {}, which GRUB's generated files do not use", first.text)));
        }
        let runs = self.runs();
        if first.is("for") {
            self.frames.push(Frame::Loop { body: runs.and(Runs::Maybe) });
        }

        if ["menuentry", "submenu", "function"].iter().any(|k| first.is(k)) {
            let defines_function = first.is("function");
            let Some(open) = words.iter().position(|w| w.is("{")) else {
                return Err(unreadable(runner, "its body does not open on the same line"));
            };
            let body = words.split_off(open + 1);
            words.pop();
            let function = (defines_function && runs != Runs::No).then(|| words.get(1).map(|w| w.text.clone())).flatten();
            if let Some(function) = &function {
                self.functions.insert(function.clone(), Some(Vec::new()));
            }
            if runs != Runs::No {
                runner.run(&self.at(line, words, runs))?;
            }
            self.bodies.push(Body { function, nested: 0 });
            if !body.is_empty() {
                self.command(line, body, runner)?;
            }
            return Ok(());
        }
        if runs == Runs::No {
            self.invert = false;
            return Ok(());
        }

        if let Some(body) = (first.expansion.is_none()).then(|| self.functions.get(&first.text).cloned()).flatten() {
            let name = first.text.clone();
            if words.len() > 1 {
                return Err(unreadable(runner, &format!("it calls function {name} with arguments, which check does not pass")));
            }
            let Some(body) = body else {
                return Err(unreadable(runner, &format!("it calls function {name}, whose body defines a menu entry or function")));
            };
            if self.calling.contains(&name) {
                return Err(unreadable(runner, &format!("function {name} calls itself")));
            }
            self.calling.push(name);
            for (called_line, called_words) in body {
                self.command(&called_line, called_words, runner)?;
            }
            self.calling.pop();
            return Ok(());
        }

        let command = self.at(line, words, runs);
        runner.run(&command)?;
        let invert = std::mem::take(&mut self.invert);
        if let Some(Frame::If { condition: condition @ Some(_), .. }) = self.frames.last_mut() {
            // The exit status of the last command before then decides the
            // branch (script/execute.c, grub_script_execute_cmdif), and a
            // '!' inverts it (grub_script_execute_cmdline).
            *condition = Some(runner.succeeded(&command)?.map(|status| status != invert));
        }
        Ok(())
    }

    /// The command of words on line, which runs as runs says.
    fn at(&self, line: &str, words: Vec<Word>, runs: Runs) -> Command {
        Command { line: line.to_string(), words, conditional: runs == Runs::Maybe, in_loop: self.in_loop() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(line: &str) -> Vec<Vec<String>> {
        split(line).unwrap().into_iter().map(|c| c.into_iter().map(|w| w.text).collect()).collect()
    }

    #[test]
    fn split_reads_quotes_escapes_separators_and_comments() {
        assert_eq!(texts("if [ \"${env_block}\" ] ; then"), vec![vec!["if", "[", "${env_block}", "]"], vec!["then"]]);
        assert_eq!(texts("set a='x y'\\ z # comment"), vec![vec!["set", "a=x y z"]]);
        assert_eq!(texts("menuentry 'x' { echo hi; }"), vec![vec!["menuentry", "x", "{", "echo", "hi"], vec!["}"]]);
        assert_eq!(texts("echo a#b"), vec![vec!["echo", "a#b"]]);
        assert!(split("echo 'open").is_err());
        assert!(split("echo a | b").is_err());
    }

    fn names(line: &str) -> Sets {
        sets(&split(line).unwrap().remove(0))
    }

    fn named(list: &[&str]) -> Sets {
        Sets::Names(list.iter().map(|n| n.to_string()).collect())
    }

    #[test]
    fn sets_follows_how_each_command_assigns() {
        assert_eq!(names("set default=\"${saved_entry}\""), named(&["default"]));
        assert_eq!(names("set ${x}=1"), Sets::Any);
        assert_eq!(names("set a=$x"), named(&["a"]));
        assert_eq!(names("menuentry_id_option=\"--id\""), named(&["menuentry_id_option"]));
        assert_eq!(names("${x}=1"), Sets::Any);
        assert_eq!(names("unset menu_show_once"), named(&["menu_show_once"]));
        assert_eq!(names("unset $x"), Sets::Any);
        assert_eq!(names("[ -z \"${blsdir}\" ]"), named(&[]));
        assert_eq!(names("password_pbkdf2 root ${GRUB2_PASSWORD}"), named(&[]));
        assert_eq!(names("source /x.cfg"), Sets::Any);
        assert_eq!(names("search --no-floppy --fs-uuid --set=boot DA53-19AA"),
            named(&["no", "floppy", "fs", "uuid", "set", "boot", "DA53", "19AA"]));
        assert_eq!(names("search -u -s 3f2a"), named(&["u", "s", "3f2a", "root"]));
        assert_eq!(names("regexp --set=$x a b"), Sets::Any);
        assert_eq!(names("$cmd"), Sets::Any);
    }

    /// Records the commands it runs, a '?' before one that may not run; the
    /// condition [ yes ] succeeds, [ no ] fails, and any other is unknown.
    #[derive(Default)]
    struct Recorder(Vec<String>);

    impl Runner for Recorder {
        type Error = String;

        fn run(&mut self, command: &Command) -> Result<(), String> {
            let words = command.words.iter().map(|w| w.text.as_str()).collect::<Vec<_>>().join(" ");
            self.0.push(format!("{}{words}", if command.conditional { "?" } else { "" }));
            Ok(())
        }

        fn succeeded(&mut self, command: &Command) -> Result<Option<bool>, String> {
            Ok(match command.words.get(1).map(|w| w.text.as_str()) {
                Some("yes") => Some(true),
                Some("no") => Some(false),
                _ => None,
            })
        }

        fn unreadable(&self, line: &str, why: &str) -> String {
            format!("{line}: {why}")
        }
    }

    fn run(script: &str) -> Vec<String> {
        let mut reader = Reader::default();
        let mut recorder = Recorder::default();
        for line in script.lines() {
            reader.line(line, &mut recorder).unwrap();
        }
        recorder.0
    }

    #[test]
    fn reader_skips_bodies_and_runs_called_functions() {
        let script = "function load_video {\n  insmod all_video\n}\nmenuentry 'x' {\n  set root=hd0\n}\nif [ a ]; then\n  load_video\nfi\n";
        assert_eq!(run(script), vec!["function load_video", "menuentry x", "[ a ]", "?insmod all_video"]);
    }

    // GRUB runs the branch after the first condition that succeeds, else the
    // else branch (script/execute.c, grub_script_execute_cmdif); a '!'
    // inverts a condition's status.
    #[test]
    fn reader_runs_the_branch_grub_takes() {
        let script = "\
if [ no ]; then set a=1; elif [ yes ]; then set b=2; else set c=3; fi
if [ maybe ]; then set d=4; else set e=5; fi
if [ yes ]; then
  if [ no ]; then set f=6; fi
  set g=7
fi
if ! [ no ]; then set h=8; fi
while [ yes ]; do set i=9; done
";
        assert_eq!(run(script), vec![
            "[ no ]", "[ yes ]", "set b=2",
            "[ maybe ]", "?set d=4", "?set e=5",
            "[ yes ]", "[ no ]", "set g=7",
            "[ no ]", "set h=8",
            "?[ yes ]", "?set i=9",
        ]);
    }
}
