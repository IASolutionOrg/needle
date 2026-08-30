use serde_json::{Value, json};
use std::env;
use std::fs;
use std::thread;
use std::time::Duration;

fn main() {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments == ["--version"] {
        println!("Antigravity CLI 1.1.22");
        return;
    }
    if arguments == ["--help"] {
        eprintln!(
            "--print --output-format --input-format --json-schema --model --effort \
             --print-timeout --sandbox --add-dir --conversation"
        );
        return;
    }

    let prompt = argument_value(&arguments, "--print").unwrap_or_default();
    let prompt_payload =
        prompt.lines().rev().find_map(|line| serde_json::from_str::<Value>(line).ok());
    let record_path =
        prompt.lines().find_map(|line| line.strip_prefix("SIM_RECORD:")).or_else(|| {
            prompt_payload
                .as_ref()
                .and_then(|value| value.get("task"))
                .and_then(Value::as_str)
                .and_then(|task| task.strip_prefix("SIM_RECORD:"))
        });
    if let Some(path) = record_path {
        let record = json!({
            "arguments": arguments,
            "cwd": env::current_dir().ok(),
        });
        fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
    }
    if let Some(path) = prompt_payload
        .as_ref()
        .and_then(|value| value.get("task"))
        .and_then(Value::as_str)
        .and_then(|task| task.strip_prefix("SIM_APPEND_RECORD:"))
    {
        use std::io::Write;
        writeln!(fs::OpenOptions::new().create(true).append(true).open(path).unwrap(), "invoked")
            .unwrap();
    }
    if let Some(milliseconds) = prompt.lines().find_map(|line| line.strip_prefix("SIM_SLEEP_MS:"))
        && let Ok(milliseconds) = milliseconds.parse::<u64>()
    {
        thread::sleep(Duration::from_millis(milliseconds));
    }
    if env::var("NEEDLE_SIM_AGY_FAIL").as_deref() == Ok("1") {
        eprintln!("simulated Antigravity failure");
        std::process::exit(1);
    }

    let schema = argument_value(&arguments, "--json-schema")
        .and_then(|value| {
            fs::read(value)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .or_else(|| serde_json::from_str::<Value>(value).ok())
        })
        .unwrap_or_else(|| json!({"type": "object"}));
    let prompt_output = prompt.lines().find_map(|line| {
        line.strip_prefix("SIM_STRUCTURED_OUTPUT:")
            .and_then(|value| serde_json::from_str::<Value>(value).ok())
    });
    let structured_output = prompt_output
        .or_else(|| {
            env::var("NEEDLE_SIM_AGY_STRUCTURED_OUTPUT")
                .ok()
                .and_then(|value| serde_json::from_str::<Value>(&value).ok())
        })
        .unwrap_or_else(|| default_structured_output(&schema, prompt_payload.as_ref()));
    let unsafe_permissions = prompt.contains("SIM_UNSAFE_PERMISSIONS");
    let opaque_tool_names = prompt.contains("SIM_OPAQUE_TOOL_NAMES");
    let missing_structured_output = prompt.contains("SIM_MISSING_STRUCTURED_OUTPUT");
    println!(
        "{}",
        json!({
            "event": "init",
            "conversation_id": "sim-antigravity-conversation",
            "init": {
                "cwd": env::current_dir().ok(),
                "tools": if opaque_tool_names {
                    json!(["host_internal_tool"])
                } else {
                    json!(["read_file", "search_files", "run_command", "write_file"])
                },
                "permission_mode": if unsafe_permissions { "always-proceed" } else { "request-review" },
                "model": argument_value(&arguments, "--model"),
                "json_schema": schema,
            }
        })
    );
    println!(
        "{}",
        json!({
            "event": "step_update",
            "step_update": {
                "conversation_id": "sim-antigravity-conversation",
                "step_index": 1,
                "state": "DONE",
                "step_type": "tool",
                "tool_name": if opaque_tool_names { "host_internal_tool" } else { "read_file" },
                "tool_info": {
                    "name": if opaque_tool_names { "host_internal_tool" } else { "read_file" },
                    "parameters": {"path": "src/lib.rs"},
                    "output": "fixture"
                }
            }
        })
    );
    if env::var("NEEDLE_SIM_AGY_OMIT_RESULT").as_deref() == Ok("1") {
        return;
    }
    let mut result = json!({
        "event": "result",
        "result": {
            "conversation_id": "sim-antigravity-conversation",
            "status": "SUCCESS",
            "response": if missing_structured_output {
                "ListDir was soft-denied in headless mode".to_owned()
            } else {
                structured_output.to_string()
            },
            "duration_seconds": 0.01,
            "num_turns": 1,
            "json_schema": schema,
            "usage": {
                "input_tokens": 10,
                "output_tokens": 5,
                "thinking_tokens": 2,
                "cache_read_tokens": 3,
                "total_tokens": 15
            }
        }
    });
    if !missing_structured_output {
        result["result"]["structured_output"] = structured_output;
    }
    println!("{result}");
}

fn default_structured_output(schema: &Value, prompt_payload: Option<&Value>) -> Value {
    let is_review = schema.pointer("/properties/verdict").is_some()
        && schema.pointer("/properties/acceptance_coverage").is_some()
        && schema.pointer("/properties/findings").is_some();
    if is_review {
        let acceptance_coverage = prompt_payload
            .and_then(|payload| payload.get("acceptance_criteria"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|criterion| {
                json!({
                    "criterion": criterion,
                    "status": "addressed",
                    "evidence": "offline simulator observed the patched fixture"
                })
            })
            .collect::<Vec<_>>();
        return json!({
            "verdict": "approved",
            "acceptance_coverage": acceptance_coverage,
            "findings": []
        });
    }
    json!({"schema": "needle.simulated-artifact/1", "facts": ["offline"]})
}

fn argument_value<'a>(arguments: &'a [String], name: &str) -> Option<&'a str> {
    arguments
        .iter()
        .position(|argument| argument == name)
        .and_then(|index| arguments.get(index + 1))
        .map(String::as_str)
}
