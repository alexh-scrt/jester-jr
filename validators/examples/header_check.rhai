// Header check validator example
//
// This script checks if specific headers are present

fn validate(ctx) {
    // Required headers
    let required = ["authorization", "x-request-id", "x-client-version"];
    
    for header in required {
        if ctx.headers.get(header) == () {
            let reason_msg = "Missing required header: " + header;
            return #{
                result: "deny",
                reason: reason_msg,
                status_code: 400
            };
        }
    }
    
    return #{ result: "allow" };
}