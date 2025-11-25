// Simple API key validator example
// 
// This script checks if the X-API-Key header contains a valid key

fn validate(ctx) {
    // Parse config - simplified for now until we integrate Rhai JSON parsing
    let valid_keys = ["key1", "key2", "key3"];
    
    // Get API key from headers
    let api_key = ctx.headers.get("x-api-key");
    
    if api_key == () {
        return #{
            result: "deny",
            reason: "Missing X-API-Key header",
            status_code: 401
        };
    }
    
    // Check if key is valid
    if valid_keys.contains(api_key) {
        return #{ result: "allow" };
    } else {
        return #{
            result: "deny",
            reason: "Invalid API key",
            status_code: 403
        };
    }
}