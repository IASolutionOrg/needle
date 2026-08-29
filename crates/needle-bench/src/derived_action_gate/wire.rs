use super::{
    DerivedActionGateError, DerivedActionGateObservation,
    MAX_DERIVED_ACTION_GATE_OBSERVATION_LINE_BYTES, MAX_DERIVED_ACTION_GATE_OBSERVATIONS,
    MAX_DERIVED_ACTION_GATE_OBSERVATIONS_BYTES,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DerivedActionObservationParse {
    pub observations: Vec<DerivedActionGateObservation>,
    pub errors: Vec<String>,
}

pub fn parse_derived_action_observations(
    bytes: &[u8],
) -> Result<DerivedActionObservationParse, DerivedActionGateError> {
    if bytes.len() > MAX_DERIVED_ACTION_GATE_OBSERVATIONS_BYTES {
        return Err(DerivedActionGateError::Bound {
            field: "observations.bytes",
            actual: bytes.len(),
            maximum: MAX_DERIVED_ACTION_GATE_OBSERVATIONS_BYTES,
        });
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|error| DerivedActionGateError::Json(error.to_string()))?;
    let mut output = DerivedActionObservationParse::default();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if output.observations.len() + output.errors.len() >= MAX_DERIVED_ACTION_GATE_OBSERVATIONS {
            return Err(DerivedActionGateError::Bound {
                field: "observations.lines",
                actual: output.observations.len() + output.errors.len() + 1,
                maximum: MAX_DERIVED_ACTION_GATE_OBSERVATIONS,
            });
        }
        if line.len() > MAX_DERIVED_ACTION_GATE_OBSERVATION_LINE_BYTES {
            output
                .errors
                .push(format!("line {} exceeds the bounded observation line size", index + 1));
            continue;
        }
        match serde_json::from_str::<DerivedActionGateObservation>(line) {
            Ok(observation) => match observation.validate() {
                Ok(()) => output.observations.push(observation),
                Err(error) => output.errors.push(format!("line {}: {error}", index + 1)),
            },
            Err(error) => output.errors.push(format!("line {}: {error}", index + 1)),
        }
    }
    Ok(output)
}
