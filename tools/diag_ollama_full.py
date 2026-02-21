#!/usr/bin/env python3
# diag_ollama_full.py - Full Ollama Diagnostic Script
"""
Run this script to diagnose Ollama issues:

    python diag_ollama_full.py

This will:
1. Check if Ollama server is running
2. List available models
3. Test model loading
4. Test actual chat completion
5. Provide specific troubleshooting steps
"""

import os
import sys
import json
import time

def print_header(text):
    print(f"\n{'='*60}")
    print(f" {text}")
    print(f"{'='*60}")

def print_status(label, status, detail=""):
    icon = "✅" if status else "❌"
    print(f"  {icon} {label}")
    if detail:
        print(f"      └─ {detail}")

def main():
    print_header("OLLAMA DIAGNOSTIC TOOL")
    
    # Configuration
    base_url = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
    model = os.getenv("OLLAMA_MODEL", "llama3:latest")
    
    print(f"\n📋 Configuration:")
    print(f"   OLLAMA_URL:        {base_url}")
    print(f"   OLLAMA_MODEL:      {model}")
    print(f"   OLLAMA_NUM_PREDICT: {os.getenv('OLLAMA_NUM_PREDICT', '2048 (default)')}")
    print(f"   OLLAMA_NUM_CTX:     {os.getenv('OLLAMA_NUM_CTX', '8192 (default)')}")
    print(f"   LLM_STREAM:         {os.getenv('LLM_STREAM', '1 (default)')}")
    
    # Try to import requests
    try:
        import requests
    except ImportError:
        print("\n❌ 'requests' library not installed. Run: pip install requests")
        sys.exit(1)
    
    results = {
        "server_reachable": False,
        "api_version": None,
        "models_available": [],
        "target_model_found": False,
        "model_loadable": False,
        "chat_works": False,
        "streaming_works": False,
    }
    recommendations = []
    
    # Test 1: Server Reachability
    print_header("TEST 1: Server Reachability")
    try:
        r = requests.get(f"{base_url}/api/version", timeout=5)
        if r.status_code == 200:
            results["server_reachable"] = True
            data = r.json()
            results["api_version"] = data.get("version", "unknown")
            print_status("Ollama server is reachable", True, f"Version: {results['api_version']}")
        else:
            print_status("Server responded but with error", False, f"Status: {r.status_code}")
            recommendations.append("Check Ollama server logs")
    except requests.exceptions.ConnectionError:
        print_status("Cannot connect to Ollama", False, f"URL: {base_url}")
        recommendations.append("Start Ollama: `ollama serve` or check if it's running")
        recommendations.append(f"Verify OLLAMA_URL is correct (current: {base_url})")
    except requests.exceptions.Timeout:
        print_status("Connection timed out", False)
        recommendations.append("Ollama may be overloaded or starting up - wait and retry")
    except Exception as e:
        print_status("Unexpected error", False, str(e))
    
    if not results["server_reachable"]:
        print_header("DIAGNOSIS: Server Not Running")
        print("\n🔧 To fix:")
        for rec in recommendations:
            print(f"   • {rec}")
        sys.exit(1)
    
    # Test 2: List Models
    print_header("TEST 2: Available Models")
    try:
        r = requests.get(f"{base_url}/api/tags", timeout=10)
        if r.status_code == 200:
            data = r.json()
            models = data.get("models", [])
            results["models_available"] = [m.get("name", "") for m in models]
            
            if results["models_available"]:
                print(f"   Found {len(results['models_available'])} model(s):")
                for m in results["models_available"]:
                    is_target = "← TARGET" if m == model or m.split(":")[0] == model.split(":")[0] else ""
                    if is_target:
                        results["target_model_found"] = True
                    print(f"     • {m} {is_target}")
            else:
                print_status("No models installed", False)
                recommendations.append(f"Pull a model: `ollama pull {model}`")
        else:
            print_status("Failed to list models", False, f"Status: {r.status_code}")
    except Exception as e:
        print_status("Error listing models", False, str(e))
    
    if not results["target_model_found"]:
        print(f"\n   ⚠️ Target model '{model}' not found!")
        recommendations.append(f"Pull the model: `ollama pull {model}`")
        if results["models_available"]:
            alt = results["models_available"][0]
            recommendations.append(f"Or use available model: `export OLLAMA_MODEL={alt}`")
    
    # Test 3: Model Loading (Generate endpoint with minimal input)
    print_header("TEST 3: Model Loading")
    if results["target_model_found"] or results["models_available"]:
        test_model = model if results["target_model_found"] else results["models_available"][0]
        print(f"   Testing model: {test_model}")
        
        try:
            # Use generate endpoint with raw=True for minimal test
            payload = {
                "model": test_model,
                "prompt": "Hi",
                "stream": False,
                "options": {"num_predict": 5}  # Just generate a few tokens
            }
            
            print(f"   Sending test request...")
            start = time.time()
            r = requests.post(f"{base_url}/api/generate", json=payload, timeout=120)
            elapsed = time.time() - start
            
            if r.status_code == 200:
                results["model_loadable"] = True
                data = r.json()
                resp_text = data.get("response", "")[:50]
                print_status(f"Model loaded and responded", True, f"Time: {elapsed:.1f}s")
                print(f"      Response preview: {repr(resp_text)}...")
            else:
                print_status(f"Model failed to respond", False, f"Status: {r.status_code}")
                try:
                    error_body = r.json()
                    print(f"      Error: {error_body.get('error', r.text[:200])}")
                except:
                    print(f"      Response: {r.text[:200]}")
                recommendations.append(f"Re-pull the model: `ollama pull {test_model}`")
                recommendations.append("Check system memory - model may be too large")
        except requests.exceptions.Timeout:
            print_status("Model loading timed out", False, "Model may be loading for first time")
            recommendations.append("Wait longer - first load can take several minutes")
            recommendations.append("Check system resources (RAM, GPU)")
        except Exception as e:
            print_status("Error during model test", False, str(e))
    else:
        print("   ⏭️ Skipped - no models available")
    
    # Test 4: Chat Completion (The actual endpoint your code uses)
    print_header("TEST 4: Chat Completion (/api/chat)")
    if results["model_loadable"]:
        test_model = model if results["target_model_found"] else results["models_available"][0]
        
        # Non-streaming test
        print(f"\n   4a. Non-streaming chat...")
        try:
            payload = {
                "model": test_model,
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": "Say 'OK' if you can understand this."}
                ],
                "stream": False,
                "options": {
                    "num_predict": 20,
                    "num_ctx": 2048,
                    "temperature": 0.1
                }
            }
            
            start = time.time()
            r = requests.post(f"{base_url}/api/chat", json=payload, timeout=60)
            elapsed = time.time() - start
            
            if r.status_code == 200:
                results["chat_works"] = True
                data = r.json()
                content = data.get("message", {}).get("content", "")
                print_status("Non-streaming chat works", True, f"Time: {elapsed:.1f}s")
                print(f"      Response: {content[:100]}")
            else:
                print_status("Non-streaming chat failed", False, f"Status: {r.status_code}")
                try:
                    error_body = r.json()
                    print(f"      Error: {error_body.get('error', r.text[:300])}")
                except:
                    print(f"      Response: {r.text[:300]}")
                recommendations.append("This is the 500 error you're experiencing!")
                recommendations.append("Try: `ollama rm {model}` then `ollama pull {model}`")
        except Exception as e:
            print_status("Non-streaming chat error", False, str(e))
        
        # Streaming test
        print(f"\n   4b. Streaming chat...")
        try:
            payload["stream"] = True
            
            start = time.time()
            with requests.post(f"{base_url}/api/chat", json=payload, stream=True, timeout=60) as r:
                if r.status_code == 200:
                    results["streaming_works"] = True
                    chunks = []
                    for line in r.iter_lines():
                        if line:
                            obj = json.loads(line.decode("utf-8"))
                            msg = obj.get("message", {})
                            if msg.get("content"):
                                chunks.append(msg["content"])
                            if obj.get("done"):
                                break
                    elapsed = time.time() - start
                    content = "".join(chunks)
                    print_status("Streaming chat works", True, f"Time: {elapsed:.1f}s")
                    print(f"      Response: {content[:100]}")
                else:
                    print_status("Streaming chat failed", False, f"Status: {r.status_code}")
                    try:
                        print(f"      Error: {r.text[:300]}")
                    except:
                        pass
        except Exception as e:
            print_status("Streaming chat error", False, str(e))
    else:
        print("   ⏭️ Skipped - model not loadable")
    
    # Summary
    print_header("SUMMARY")
    all_pass = all([
        results["server_reachable"],
        results["target_model_found"] or results["models_available"],
        results["model_loadable"],
        results["chat_works"],
    ])
    
    if all_pass:
        print("\n   🎉 All tests passed! Ollama is working correctly.")
        print("\n   If you're still getting 500 errors in your pipeline, check:")
        print("   • Environment variables are set in the same shell")
        print("   • No proxy interfering (HTTP_PROXY, HTTPS_PROXY)")
        print("   • Request payload size (may need to reduce num_ctx)")
    else:
        print("\n   ⚠️ Some tests failed. See recommendations below.")
    
    if recommendations:
        print_header("RECOMMENDATIONS")
        seen = set()
        for rec in recommendations:
            if rec not in seen:
                print(f"   • {rec}")
                seen.add(rec)
    
    # Additional debug info
    print_header("ENVIRONMENT")
    print(f"   Python: {sys.version.split()[0]}")
    print(f"   Platform: {sys.platform}")
    
    # Check for common issues
    proxy = os.getenv("HTTP_PROXY") or os.getenv("HTTPS_PROXY") or os.getenv("http_proxy") or os.getenv("https_proxy")
    if proxy:
        print(f"\n   ⚠️ Proxy detected: {proxy}")
        print(f"   This might interfere with localhost connections!")
        print(f"   Try: `export NO_PROXY=localhost,127.0.0.1`")
    
    print("\n" + "=" * 60)
    
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())