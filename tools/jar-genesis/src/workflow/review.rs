/// Run the review workflow: process a /review comment.
pub fn run(
    _pr: u64,
    _comment_author: &str,
    _comment_body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: implement
    eprintln!("workflow review: not yet implemented");
    std::process::exit(1);
}
