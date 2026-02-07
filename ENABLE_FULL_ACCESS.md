# How to Enable Full Router API Access

## 🎯 Goal
Get full admin access to unlock all router APIs (WiFi settings, device list, router info, etc.)

---

## 🔍 Current Situation

**What Works Now:**
- ✅ Login as user: `user` / `7dWU!fNf`
- ✅ MAC filtering API (block/unblock devices)

**What Doesn't Work:**
- ❌ Device list API (405 error)
- ❌ WiFi settings API (405 error)  
- ❌ Router info API (405 error)

**Why:** These APIs might require **admin** account instead of **user** account.

---

## 📝 Steps to Enable Full Access

### Step 1: Find Admin Password

The router has two accounts:
1. **user** - Limited access (current)
2. **admin** - Full access (TelecomAccount)

**Method A: Check Router Label**
- Look at the bottom/back of your router
- Find sticker with admin credentials
- Usually says "Admin Password:" or "Superuser:"

**Method B: Check Router Web Interface**
1. Open browser: http://192.168.1.1
2. Login as **user** / **7dWU!fNf**
3. Go to: **System** → **User Management** or **Administration**
4. Check if admin password is shown or can be changed

**Method C: Check Your ISP Documents**
- China Telecom may have provided admin credentials
- Check installation documents
- Contact ISP support

**Method D: Common China Telecom Admin Passwords**
Try these in browser at http://192.168.1.1:
- `admin` / `admin`
- `admin` / `ct@admin`
- `admin` / `telecomadmin`  
- `admin` / `chinatelecom`
- `admin` / (same as veriCode: `7dWU!fNf`)
- `telecomadmin` / `telecomadmin`
- `ct` / `ct`

**Method E: Router Reset (LAST RESORT)**
- Press reset button for 10 seconds
- This will restore factory defaults
- **WARNING:** You'll lose all settings!

---

### Step 2: Update Code to Use Admin Account

Once you find the admin password, update `router_manager.py`:

```python
# Change line 17 from:
def __init__(self, router_ip="192.168.1.1", username="user", password="7dWU!fNf"):

# To:
def __init__(self, router_ip="192.168.1.1", username="admin", password="YOUR_ADMIN_PASSWORD"):
```

---

### Step 3: Test Admin Access

Run this test:

```bash
python -c "from router_manager import RouterManager; r = RouterManager('192.168.1.1', 'admin', 'YOUR_PASSWORD'); print('Login:', r.login()); print('Devices:', r.get_connected_devices())"
```

If it works, you'll see device list!

---

## 🔧 Alternative: Web Scraping

If admin API still doesn't work, we can **scrape the HTML pages**:

### How It Works:
1. Login to router
2. Load HTML page (e.g., `landevice.html`)
3. Parse HTML to extract data
4. Convert to JSON format

### Implementation:

```python
from bs4 import BeautifulSoup

def get_devices_from_html(self):
    """Get devices by scraping HTML page"""
    # Login first
    self.login()
    
    # Get device page
    response = self.session.get(f'{self.base_url}/landevice.html')
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Parse table or JavaScript data
    devices = []
    # Extract device info from HTML...
    
    return devices
```

**Pros:**
- Works even if APIs are disabled
- Can access any visible data

**Cons:**
- Slower than API
- Breaks if HTML changes
- More complex parsing

---

## 🎯 Recommendation by Priority

### Priority 1: Find Admin Password ⭐⭐⭐
- Check router label
- Check web interface  
- Contact ISP

**If successful:** Full API access unlocked!

### Priority 2: Use Current Limited Access ⭐⭐
- Stick with `user` account
- Focus on MAC filtering (what works)
- Create simple GUI for blocking devices

**Pros:** Works now, no extra effort

### Priority 3: Web Scraping ⭐
- Parse HTML pages for data
- More complex implementation
- Last resort option

---

## 📞 Next Steps

**Option A: You Know Admin Password**
```text
Tell me the admin password and I'll update the code immediately!
```

**Option B: You Don't Know Admin Password**
```text
1. Try logging into http://192.168.1.1 in browser
2. Try different usernames (admin, telecomadmin, ct, etc.)
3. Check router label
4. Let me know what you find
```

**Option C: Keep Current Access**
```text
I'll create a simplified GUI that works with current limited access
- Block/unblock devices
- View blocked list
- Clean, simple interface
```

---

## 🔑 What's Your Admin Password?

Once you find it, update here:

```python
# In router_manager.py, line 17:
username = "admin"  # Change from "user"
password = "??????"  # Your admin password here
```

Then run:
```bash
python router_gui.py
```

And you'll have **FULL ACCESS!** 🎉

---

**Which option do you want to try first?**

1. Find admin password (I'll help guide you)
2. Implement web scraping (I'll write the code)
3. Use current limited access (I'll simplify the GUI)

Let me know!
