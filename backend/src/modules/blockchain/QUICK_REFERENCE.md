# RPC Fallback & Retry - Quick Reference

## 🚀 Quick Setup (2 Minutes)

### 1. Add to `.env`
```env
# Fallback endpoints (comma-separated)
SOROBAN_RPC_FALLBACK_URLS=https://backup1.stellar.org,https://backup2.stellar.org
HORIZON_FALLBACK_URLS=https://backup1-horizon.stellar.org

# Optional: Tune retry behavior
RPC_MAX_RETRIES=3
RPC_RETRY_DELAY=1000
RPC_TIMEOUT=10000
```

### 2. That's it! 
All existing code automatically uses retry and failover. No code changes needed.

---

## 📊 Monitor Status

### Check Current Endpoints
```bash
curl http://localhost:3001/blockchain/rpc/status
```

### In Code
```typescript
const status = stellarService.getEndpointsStatus();
console.log('Active RPC:', status.rpc.currentUrl);
```

---

## 🔍 Log Patterns

### Normal Operation
```
[StellarService] Stellar Service Initialized
[StellarService] Configured 3 RPC endpoint(s) and 2 Horizon endpoint(s)
```

### Retry (Warning)
```
[RpcClientWrapper] RPC request failed on https://primary.stellar.org (attempt 1/3): Network error
```

### Failover (Warning)
```
[RpcClientWrapper] Successfully failed over to rpc endpoint: https://backup.stellar.org after 4 attempts
```

### Critical (Error)
```
[RpcClientWrapper] CRITICAL: All retries exhausted for rpc endpoint https://primary.stellar.org
[RpcClientWrapper] CRITICAL: All rpc endpoints failed after 9 total attempts
```

---

## ⚙️ Configuration Presets

### Development (Fast Fail)
```env
RPC_MAX_RETRIES=1
RPC_RETRY_DELAY=500
RPC_TIMEOUT=5000
```

### Production (Reliable)
```env
RPC_MAX_RETRIES=5
RPC_RETRY_DELAY=1000
RPC_TIMEOUT=15000
```

### Testing (Aggressive)
```env
RPC_MAX_RETRIES=2
RPC_RETRY_DELAY=100
RPC_TIMEOUT=3000
```

---

## 🛠️ Common Tasks

### Add New Fallback Endpoint
```env
# Just append to the comma-separated list
SOROBAN_RPC_FALLBACK_URLS=existing1.com,existing2.com,new-endpoint.com
```

### Change Primary Endpoint
```env
# Swap primary with a more reliable backup
SOROBAN_RPC_URL=https://reliable-backup.stellar.org
SOROBAN_RPC_FALLBACK_URLS=https://old-primary.stellar.org,https://other-backup.stellar.org
```

### Disable Fallback (Testing)
```env
# Leave fallback URLs empty
SOROBAN_RPC_FALLBACK_URLS=
HORIZON_FALLBACK_URLS=
```

---

## 🧪 Testing Failover

### Simulate Primary Failure
```env
# Use invalid primary, valid backup
SOROBAN_RPC_URL=https://invalid-endpoint.stellar.org
SOROBAN_RPC_FALLBACK_URLS=https://soroban-testnet.stellar.org
```

### Watch Logs
```bash
npm run start:dev | grep -E "(CRITICAL|failed over)"
```

---

## 📈 Performance

| Scenario | Typical Time | Max Time |
|----------|-------------|----------|
| Success (no retry) | 100-500ms | 1s |
| Retry (same endpoint) | 1-3s | 7s |
| Failover (next endpoint) | 4-8s | 15s |
| All endpoints down | 30-60s | 90s |

---

## 🚨 Alerts Setup

### Warning Alert (Investigate)
- **Pattern**: `"RPC request failed"`
- **Threshold**: > 10 per minute
- **Action**: Check endpoint health

### Critical Alert (Urgent)
- **Pattern**: `"CRITICAL: All retries exhausted"`
- **Threshold**: > 1 per minute
- **Action**: Verify endpoint availability

### Emergency Alert (Immediate)
- **Pattern**: `"CRITICAL: All .* endpoints failed"`
- **Threshold**: Any occurrence
- **Action**: System may be down, investigate immediately

---

## 💡 Best Practices

### ✅ Do
- Configure at least 2-3 fallback endpoints
- Use endpoints in different geographic regions
- Monitor `/blockchain/rpc/status` regularly
- Set up log alerts for CRITICAL messages
- Test failover in staging before production
- Keep fallback URLs updated

### ❌ Don't
- Use only one endpoint (no redundancy)
- Set timeout too low (< 3000ms)
- Set retries too high (> 10)
- Ignore CRITICAL log messages
- Use HTTP endpoints in production
- Forget to test failover behavior

---

## 🔧 Troubleshooting

### Problem: Slow responses
**Solution**: Reduce timeout and retries
```env
RPC_TIMEOUT=5000
RPC_MAX_RETRIES=2
```

### Problem: Too many failovers
**Solution**: Check primary endpoint health, consider swapping
```bash
curl https://your-primary-endpoint.stellar.org/health
```

### Problem: All endpoints failing
**Solution**: Check network connectivity and Stellar network status
```bash
# Test endpoint manually
curl https://soroban-testnet.stellar.org/health
```

---

## 📚 Documentation

- **Full Documentation**: [RPC_FALLBACK.md](./RPC_FALLBACK.md)
- **Usage Examples**: [EXAMPLE_USAGE.md](./EXAMPLE_USAGE.md)
- **Architecture**: [ARCHITECTURE.md](./ARCHITECTURE.md)
- **Implementation**: [IMPLEMENTATION_SUMMARY.md](../../IMPLEMENTATION_SUMMARY.md)

---

## 🆘 Support

### Check Logs
```bash
# View recent logs
npm run start:dev

# Filter for RPC issues
npm run start:dev | grep -i "rpc\|stellar"
```

### Verify Configuration
```typescript
// In your code
const status = stellarService.getEndpointsStatus();
console.log(JSON.stringify(status, null, 2));
```

### Test Endpoints Manually
```bash
# Test RPC endpoint
curl https://soroban-testnet.stellar.org/health

# Test Horizon endpoint
curl https://horizon-testnet.stellar.org/
```

---

## 📝 Cheat Sheet

| Task | Command/Code |
|------|-------------|
| Check status | `GET /blockchain/rpc/status` |
| Get endpoints | `stellarService.getEndpointsStatus()` |
| Add fallback | Add to `SOROBAN_RPC_FALLBACK_URLS` |
| Change primary | Update `SOROBAN_RPC_URL` |
| Tune retries | Set `RPC_MAX_RETRIES` |
| Tune timeout | Set `RPC_TIMEOUT` |
| View logs | `npm run start:dev` |
| Run tests | `pnpm test stellar.service` |

---

## 🎯 Key Takeaways

1. **Zero Code Changes**: Existing code automatically gets retry/failover
2. **Configure via ENV**: All settings in environment variables
3. **Monitor Logs**: Watch for CRITICAL messages
4. **Test Failover**: Simulate failures in staging
5. **Multiple Backups**: Use 2-3 fallback endpoints minimum

---

**Issue Reference**: #195 - Implement Web3 RPC Fallback & Retry Strategy
