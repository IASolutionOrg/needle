use std::{env, fs, path::PathBuf};

fn main() {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.first().map(String::as_str) {
        Some("--version") => println!("codex-cli 0.144.0"),
        Some("app-server") if arguments.iter().any(|argument| argument == "--help") => {
            println!("--listen <URL>\n--strict-config\n--experimental");
        }
        Some("app-server")
            if arguments.get(1).map(String::as_str) == Some("generate-json-schema") =>
        {
            let out = arguments
                .iter()
                .position(|argument| argument == "--out")
                .and_then(|index| arguments.get(index + 1))
                .map(PathBuf::from)
                .expect("schema output directory");
            fs::create_dir_all(out.join("v2")).unwrap();
            let methods = r#"{
                "methods": [
                    "thread/start", "turn/start", "turn/interrupt", "thread/delete",
                    "item/agentMessage/delta", "item/commandExecution/requestApproval",
                    "item/fileChange/requestApproval", "turn/completed",
                    "thread/tokenUsage/updated"
                ]
            }"#;
            fs::write(out.join("codex_app_server_protocol.schemas.json"), methods).unwrap();
            fs::write(out.join("codex_app_server_protocol.v2.schemas.json"), methods).unwrap();
            fs::write(
                out.join("v2/ThreadStartParams.json"),
                r#"{"properties":{"approvalPolicy":{},"cwd":{},"model":{},"sandbox":{}}}"#,
            )
            .unwrap();
            fs::write(
                out.join("v2/TurnStartParams.json"),
                r#"{"properties":{"approvalPolicy":{},"input":{},"outputSchema":{},"sandboxPolicy":{},"threadId":{}}}"#,
            )
            .unwrap();
            fs::write(
                out.join("v2/TurnInterruptParams.json"),
                r#"{"properties":{"threadId":{},"turnId":{}}}"#,
            )
            .unwrap();
            fs::write(
                out.join("CommandExecutionRequestApprovalParams.json"),
                r#"{"properties":{"itemId":{},"threadId":{},"turnId":{}}}"#,
            )
            .unwrap();
            fs::write(
                out.join("CommandExecutionRequestApprovalResponse.json"),
                r#"{"properties":{"decision":{}}}"#,
            )
            .unwrap();
            fs::write(
                out.join("FileChangeRequestApprovalResponse.json"),
                r#"{"properties":{"decision":{}}}"#,
            )
            .unwrap();
            fs::write(
                out.join("v2/ThreadTokenUsageUpdatedNotification.json"),
                r#"{"properties":{"threadId":{},"tokenUsage":{}}}"#,
            )
            .unwrap();
            fs::write(
                out.join("v2/TurnCompletedNotification.json"),
                r#"{"properties":{"threadId":{},"turn":{}}}"#,
            )
            .unwrap();
        }
        _ => {}
    }
}
