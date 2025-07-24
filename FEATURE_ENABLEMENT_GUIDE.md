# 🔧 FEATURE ENABLEMENT GUIDE

## 🎯 **Why Features Are Skipped**

The features are skipped by default for **safety and performance reasons**:

### **⚠️ Attack Simulation**
- **Why Skipped**: Simulates real attacks that could be dangerous
- **Safety**: Prevents accidental damage to production systems
- **Performance**: Adds significant time to scans

### **🔄 Daily Scraping**
- **Why Skipped**: Requires internet access and web scraping
- **Safety**: May trigger rate limiting or security alerts
- **Performance**: Adds overhead to scanning process

---

## 🚀 **How to Enable Features**

### **🔍 Enable Attack Simulation**
```bash
# Add --simulate flag to enable attack simulation
python3 main.py "your-target-url" --simulate

# Example with curl command
python3 main.py 'curl "https://api.example.com/test"' --simulate
```

### **🔄 Enable Daily Scraping**
```bash
# Add --daily flag to enable daily scraping
python3 main.py "your-target-url" --daily

# Example with both features
python3 main.py "your-target-url" --simulate --daily
```

### **🔧 Enable Dynamic Checks**
```bash
# Add --dynamic-checks flag for real-time updates
python3 main.py "your-target-url" --dynamic-checks

# Full feature set
python3 main.py "your-target-url" --simulate --daily --dynamic-checks
```

---

## 🏆 **Hackathon Demo Options**

### **🎯 Safe Demo (Recommended)**
```bash
# Basic scan - safe and fast
python3 main.py "your-target-url"

# With severity control
python3 main.py "your-target-url" --severity critical
```

### **🚀 Advanced Demo (Show All Features)**
```bash
# Full feature demonstration
python3 main.py "your-target-url" --simulate --daily --dynamic-checks --severity all
```

### **⚡ Fast Demo (Quick Results)**
```bash
# Critical vulnerabilities only
python3 main.py "your-target-url" --severity critical

# High priority checks
python3 main.py "your-target-url" --severity high
```

---

## 📊 **Feature Comparison**

| Feature | Flag | Purpose | Time Impact | Safety Level |
|---------|------|---------|-------------|--------------|
| **Basic Scan** | None | Core security testing | ~5-20 min | ✅ Safe |
| **Attack Simulation** | `--simulate` | Simulate real attacks | +10-15 min | ⚠️ Caution |
| **Daily Scraping** | `--daily` | Get latest attack vectors | +5-10 min | ⚠️ Caution |
| **Dynamic Checks** | `--dynamic-checks` | Real-time updates | +2-5 min | ✅ Safe |

---

## 🎯 **Recommended Demo Flow**

### **🏆 Stage 1: Basic Demo**
```bash
# Show core capabilities
python3 main.py "https://api.example.com/test" --severity all
```

### **🚀 Stage 2: Advanced Demo**
```bash
# Show attack simulation
python3 main.py "https://api.example.com/test" --simulate --severity critical
```

### **🔧 Stage 3: Full Demo**
```bash
# Show all features
python3 main.py "https://api.example.com/test" --simulate --daily --dynamic-checks --severity all
```

---

## ⚠️ **Safety Considerations**

### **🔒 Production Systems**
- **Never use** `--simulate` on production systems
- **Test on** staging/development environments only
- **Use** `--severity critical` for quick safety checks

### **🌐 Internet Access**
- **Daily scraping** requires internet access
- **May trigger** rate limiting on some sites
- **Use responsibly** to avoid being blocked

### **⚡ Performance**
- **Full scans** can take 20+ minutes
- **Use severity levels** to control scan time
- **Start with** `--severity critical` for quick results

---

## 🎉 **Perfect Hackathon Demo**

### **✅ Recommended Approach**
1. **Start Safe**: Use basic scan first
2. **Show Results**: Display comprehensive report
3. **Enable Features**: Demonstrate advanced capabilities
4. **Explain Safety**: Show why features are disabled by default
5. **Highlight Quality**: Emphasize professional output

### **🏆 Demo Script**
```bash
# 1. Basic scan (safe and fast)
python3 main.py "your-target-url" --severity all

# 2. Show attack simulation (with caution)
python3 main.py "your-target-url" --simulate --severity critical

# 3. Show dynamic updates
python3 main.py "your-target-url" --dynamic-checks --severity high
```

**🏆 RESULT: PROFESSIONAL DEMO WITH SAFETY CONTROLS!** 🚀 