// ===== Globals / caches (OUTSIDE DOMContentLoaded) =====
window.businessCache  = window.businessCache  || new Map();
window.calendarCache  = window.calendarCache  || new Map();
window.categoryCache  = window.categoryCache  || new Map();
window.serviceCache   = window.serviceCache   || new Map();

let editingBusinessId  = null;
let editingCalendarId  = null;
let editingCategoryId  = null;
let editingServiceId   = null;

// Whoever picks the active business should set this:
// e.g. when user selects from a dropdown, update window.currentBusinessId
window.currentBusinessId = window.currentBusinessId || null;
// ---- helpers (place near top of file) ----
if (!window.serviceCache) window.serviceCache = new Map();

function firstDefined(...vals) {
  for (const v of vals) if (v !== undefined && v !== null && v !== "") return v;
  return undefined;
}

function formatMoney(v) {
  const n = Number(v);
  if (!isFinite(n)) return ""; // show blank if not a number
  return n.toLocaleString(undefined, { style: "currency", currency: "USD", maximumFractionDigits: 2 });
}

document.addEventListener("DOMContentLoaded", () => {
  (async () => {
    const loginStatus = document.getElementById("login-status-text");
    const openLoginBtn = document.getElementById("open-login-popup-btn");
    const logoutBtn    = document.getElementById("logout-btn");

    // Show login status
    fetch("/check-login")
      .then(res => res.json())
      .then(data => {
        if (data.loggedIn) {
          loginStatus.textContent = `Hi, ${data.firstName ?? ''} 👋`;
          if (logoutBtn)    logoutBtn.style.display = "inline-block";
          if (openLoginBtn) openLoginBtn.style.display = "none";

          // ✅ Load businesses after confirming logged in Page Loader
          loadBusinessDropdown();
            loadBusinessList();
            loadCalendarList();
            bindCategoryUI();
            bindServiceUI();
initTemplatePicker();

        } else {
          loginStatus.textContent = "Not logged in";
          if (logoutBtn)    logoutBtn.style.display = "none";
          if (openLoginBtn) openLoginBtn.style.display = "inline-block";
        }
      });
 if (typeof window.loadTemplateSelection === 'function') {
  window.loadTemplateSelection();
}

    // Logout
    if (logoutBtn) {
      logoutBtn.addEventListener("click", async () => {
        try {
          const res = await fetch("/logout");
          const result = await res.json();
          if (res.ok) {
            alert("👋 Logged out!");
            window.location.href = "signup.html";
          } else {
            alert(result.message || "Logout failed.");
          }
        } catch (err) {
          console.error("Logout error:", err);
          alert("Something went wrong during logout.");
        }
      });
    }

    // Open Login Popup
    if (openLoginBtn) {
      openLoginBtn.addEventListener("click", () => {
        document.getElementById("popup-login").style.display = "block";
        document.getElementById("popup-overlay").style.display = "block";
        document.body.classList.add("popup-open");
      });
    }

    // Handle Login Submit
    const loginForm = document.getElementById("login-form");
    if (loginForm) {
      loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const email = document.getElementById("login-email").value.trim();
        const password = document.getElementById("login-password").value.trim();
        if (!email || !password) return alert("Please enter both email and password.");

        try {
          const res = await fetch("/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password }),
          });
          const result = await res.json();

          if (res.ok) {
            alert("✅ Logged in!");
            if (typeof closeLoginPopup === 'function') closeLoginPopup();
            location.reload();
          } else {
            alert(result.message || "Login failed.");
          }
        } catch (err) {
          console.error("Login error:", err);
          alert("Something went wrong.");
        }
      });
    }


    ////////////////////////////////////////////////////////////////////
                    //Menu Section
//Click Overlay to close popups
document.addEventListener("DOMContentLoaded", () => {
  const overlay = document.getElementById("popup-overlay");
  if (overlay) overlay.addEventListener("click", closeAllPopups);
});



                    //Tab Swithing 
                      // Tab Switching
  const optionTabs = document.querySelectorAll(".option");
  const tabSections = document.querySelectorAll("[id$='-section']");

optionTabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    optionTabs.forEach(t => t.classList.remove("active"));
    tabSections.forEach(section => section.style.display = "none");

    tab.classList.add("active");
    const targetId = `${tab.dataset.id}-section`;
    const section = document.getElementById(targetId);
    if (section) section.style.display = "block";
  });
});

    ////////////////////////////////////////////////////////////////////
                    //Business Section

    // ✅ OPEN BUSINESS POPUP FIX
// Add Business (create mode)
const openBtn = document.getElementById("open-business-popup-button");
const businessPopup = document.getElementById("popup-add-business");
const overlay = document.getElementById("popup-overlay");

function openBusinessCreate() {
  // clear any edit state (we'll also define this outside later)
  window.editingBusinessId = null;

  // reset form fields
  const form = document.getElementById("popup-add-business-form");
  if (form) form.reset();

  // reset image preview (optional)
  const img = document.getElementById("current-hero-image");
  const noImg = document.getElementById("no-image-text");
  if (img) img.style.display = "none";
  if (noImg) noImg.style.display = "block";
  const file = document.getElementById("image-upload");
  if (file) file.value = "";

  // show correct buttons + title for CREATE
  const save = document.getElementById("save-button");
  const upd  = document.getElementById("update-button");
  const del  = document.getElementById("delete-button");
  if (save) save.style.display = "inline-block";
  if (upd)  upd.style.display  = "none";
  if (del)  del.style.display  = "none";
  const title = document.getElementById("popup-title");
  if (title) title.textContent = "Business";

  // open popup
  if (businessPopup && overlay) {
    businessPopup.style.display = "block";
    overlay.style.display = "block";
    document.body.classList.add("popup-open");
  }
}

if (openBtn && businessPopup && overlay) {
  openBtn.addEventListener("click", openBusinessCreate);
}

  })(); // end async IIFE

  
 //Save Business
 const form = document.getElementById("popup-add-business-form");
if (form) {
  form.addEventListener("submit", async (e) => { /* ... */ });
}

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const TYPE_NAME = "Business"; // must match your Data Type name exactly
    const submitBtn = document.getElementById("save-button");
    const prevText = submitBtn ? submitBtn.textContent : "";

    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = "Saving...";
    }

    // collect values from the form
    const values = {
      businessName: document.getElementById("popup-business-name-input").value.trim(),
      yourName: document.getElementById("popup-your-name-input").value.trim(),
      phoneNumber: document.getElementById("popup-business-phone-number-input").value.trim(),
      locationName: document.getElementById("popup-business-location-name-input").value.trim(),
      businessAddress: document.getElementById("popup-business-address-input").value.trim(),
      businessEmail: document.getElementById("popup-business-email-input").value.trim()
      // heroImage: we'll add later
    };

    try {
      // call your server route
      const res = await fetch(`/api/records/${encodeURIComponent(TYPE_NAME)}`, {
        method: "POST",
        credentials: "include",                  // required because ensureAuthenticated
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ values })
      });

      if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try {
          const err = await res.json();
          if (err?.error) msg += ` - ${err.error}`;
        } catch {}
        throw new Error(msg);
      }

      const created = await res.json();
      console.log("Created:", created);

      alert("Business saved!");
      form.reset();
     
//
await loadBusinessDropdown({ preserve: false, selectId: created._id });
await loadBusinessList();
closeAllPopups()

    } catch (err) {
      console.error(err);
      alert("Error saving business: " + err.message);
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = prevText;
      }
    }
  });


  //Update Business
  const updateBtn = document.getElementById("update-button");
const deleteBtn = document.getElementById("delete-button");

if (updateBtn && !updateBtn.dataset.bound) {
  updateBtn.addEventListener("click", async () => {
    if (!editingBusinessId) return alert("No business selected.");
    const TYPE = "Business";

    const values = {
      businessName: document.getElementById("popup-business-name-input").value.trim(),
      yourName: document.getElementById("popup-your-name-input").value.trim(),
      phoneNumber: document.getElementById("popup-business-phone-number-input").value.trim(),
      locationName: document.getElementById("popup-business-location-name-input").value.trim(),
      businessAddress: document.getElementById("popup-business-address-input").value.trim(),
      businessEmail: document.getElementById("popup-business-email-input").value.trim()
      // add heroImageUrl later if you want to support editing image
    };

    updateBtn.disabled = true;
    const prev = updateBtn.textContent;
    updateBtn.textContent = "Updating…";

    try {
      const res = await fetch(`/api/records/${encodeURIComponent(TYPE)}/${editingBusinessId}`, {
        method: "PATCH",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ values })
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      await res.json();

      alert("Business updated!");
      closeAllPopups()
      await loadBusinessDropdown({ preserve: true, selectId: editingBusinessId });
      await loadBusinessList();
    } catch (e) {
      console.error(e);
      alert("Error updating business: " + e.message);
    } finally {
      updateBtn.disabled = false;
      updateBtn.textContent = prev;
    }
  });
  updateBtn.dataset.bound = "1";
}

//Delete business
if (deleteBtn && !deleteBtn.dataset.bound) {
  deleteBtn.addEventListener("click", async () => {
    if (!editingBusinessId) return;
    if (!confirm("Delete this business? This cannot be undone.")) return;

    const TYPE = "Business";
    deleteBtn.disabled = true;
    const prev = deleteBtn.textContent;
    deleteBtn.textContent = "Deleting…";

    try {
      const res = await fetch(`/api/records/${encodeURIComponent(TYPE)}/${editingBusinessId}`, {
        method: "DELETE",
        credentials: "include"
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      alert("Business deleted.");
      closeAllPopups()
      // clear selection if it was selected
      const saved = sessionStorage.getItem("selectedBusinessId");
      if (saved === editingBusinessId) sessionStorage.removeItem("selectedBusinessId");

      await loadBusinessDropdown({ preserve: true });
      await loadBusinessList();
      await loadCalendarList(); // calendars tied to it might change visibility
    } catch (e) {
      console.error(e);
      alert("Error deleting business: " + e.message);
    } finally {
      deleteBtn.disabled = false;
      deleteBtn.textContent = prev;
    }
  });
  deleteBtn.dataset.bound = "1";
}







    ////////////////////////////////////////////////////////////////////
                    //Calendar Section
  const openCalendarBtn = document.getElementById("open-calendar-button");
const calendarPopup   = document.getElementById("popup-add-calendar");
const overlay         = document.getElementById("popup-overlay");

if (openCalendarBtn && calendarPopup && overlay) {
  openCalendarBtn.addEventListener("click", async () => {
    await loadCalendarBusinessOptions();        // fill the dropdown
    calendarPopup.style.display = "block";
    overlay.style.display = "block";
    document.body.classList.add("popup-open");
  });
}

// Allow clicking overlay to close everything
if (overlay) {
  overlay.addEventListener("click", closeAllPopups);
}

//Save Calendar 
const saveCalBtn   = document.getElementById("save-calendar-button");
const calNameInput = document.getElementById("popup-calendar-name-input");
const calBizSelect = document.getElementById("dropdown-calendar-business");

if (saveCalBtn && calNameInput && calBizSelect) {
  saveCalBtn.addEventListener("click", async () => {
    const TYPE_NAME = "Calendar"; // must match your Data Type name exactly
    const calendarName = calNameInput.value.trim();
    const businessId   = calBizSelect.value;

    if (!calendarName) return alert("Please enter a calendar name.");
    if (!businessId)   return alert("Please choose a business.");

    saveCalBtn.disabled = true;
    const prevText = saveCalBtn.textContent;
    saveCalBtn.textContent = "Saving…";

    try {
      const res = await fetch(`/api/records/${encodeURIComponent(TYPE_NAME)}`, {
        method: "POST",
        credentials: "include", // required by ensureAuthenticated
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          values: {
            // Use field names that exist on your Calendar data type:
            // if you created fields called "name" instead of "calendarName", change this accordingly.
            calendarName,
            businessId      // store the selected Business record _id as a reference
          }
        })
      });

      if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try {
          const err = await res.json();
          if (err?.error) msg += ` - ${err.error}`;
        } catch {}
        throw new Error(msg);
      }

      const created = await res.json();
      console.log("Calendar created:", created);

      alert("Calendar saved!");
      calNameInput.value = "";                 // clear name
      // (optional) refresh any calendar lists you show elsewhere
       await loadCalendarList();

      closeAddCalendarPopup();                 // hide popup + overlay

    } catch (e) {
      console.error(e);
      alert("Error saving calendar: " + e.message);
    } finally {
      saveCalBtn.disabled = false;
      saveCalBtn.textContent = prevText;
    }
  });
}


        ////////////////////////////////////////////////////////////////////
                    //  Category Section
 //Open Add Category Popup
 const openCategoryBtn = document.getElementById("open-category-popup-button");
const categoryPopup   = document.getElementById("popup-add-category");


if (openCategoryBtn && categoryPopup && overlay) {
  openCategoryBtn.addEventListener("click", async () => {

  await loadBusinessOptions('dropdown-category-business');  // ⬅️ fill the dropdown

     // 2) Preselect from main dropdown/session if available
    const bizSel = document.getElementById('dropdown-category-business');
    const currentBiz =
      document.getElementById('business-dropdown')?.value ||
      sessionStorage.getItem('selectedBusinessId') || '';

    if (currentBiz && bizSel?.querySelector(`option[value="${currentBiz}"]`)) {
      bizSel.value = currentBiz;
    }

    // 3) Load calendars for the selected business
    await loadCalendarOptions('dropdown-business-calendar', bizSel?.value);

    categoryPopup.style.display = 'block';
    overlay.style.display = 'block';
    document.body.classList.add('popup-open');
  });
}

  // ⬇️ Bind the CHANGE handler once (outside the click handler)
  const popupBizSel = document.getElementById("dropdown-category-business");
  if (popupBizSel && !popupBizSel.dataset.bound) {
    popupBizSel.addEventListener("change", async () => {
      await loadCalendarOptions("dropdown-business-calendar", popupBizSel.value);
    });
    popupBizSel.dataset.bound = "1"; // prevent double-binding
  }

// (Optional) Let users click the overlay to close
if (overlay) overlay.addEventListener("click", closeCategoryPopup);
    

//Save Category 
// === Save Category ===
const saveCategoryBtn = document.getElementById("save-category-button");
const catNameInput    = document.getElementById("popup-category-name-input"); // <-- make sure this ID matches your input
const catBizSelect    = document.getElementById("dropdown-category-business");
const catCalSelect    = document.getElementById("dropdown-business-calendar");

if (saveCategoryBtn && catBizSelect && catCalSelect) {
  saveCategoryBtn.addEventListener("click", async () => {
    const TYPE_NAME   = "Category"; // must match your Data Type exactly
    const categoryName = catNameInput ? catNameInput.value.trim() : "";
    const businessId   = catBizSelect.value;
    const calendarId   = catCalSelect.value;

    // basic validation (adjust if your data type uses different fields)
    if (!businessId)   return alert("Please choose a business.");
    if (!calendarId)   return alert("Please choose a calendar.");
    if (!categoryName) return alert("Please enter a category name.");

    const prevText = saveCategoryBtn.textContent;
    saveCategoryBtn.disabled = true;
    saveCategoryBtn.textContent = "Saving…";

    try {
      const res = await fetch(`/api/records/${encodeURIComponent(TYPE_NAME)}`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          values: {
            // Use your actual field names here:
            categoryName,   // or "name"
            businessId,     // reference to Business record _id
            calendarId      // reference to Calendar record _id
          }
        })
      });

      if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try {
          const err = await res.json();
          if (err?.error) msg += ` - ${err.error}`;
        } catch {}
        throw new Error(msg);
      }

      const created = await res.json();
      console.log("Category created:", created);

      alert("Category saved!");
      if (catNameInput) catNameInput.value = "";

      await loadCategoryList();
      closeCategoryPopup();

      // If you’ll show categories in a list later:
      // await loadCategoryList();

    } catch (e) {
      console.error(e);
      alert("Error saving category: " + e.message);
    } finally {
      saveCategoryBtn.disabled = false;
      saveCategoryBtn.textContent = prevText;
    }
  });
}

        ////////////////////////////////////////////////////////////////////
                    //Service Section                

//Open Add Service Popup
// Add Service (create mode)
const openServiceBtn = document.getElementById("open-service-popup-button");
const servicePopup   = document.getElementById("popup-add-service");


const svcBizSel = document.getElementById("dropdown-service-business");
const svcCalSel = document.getElementById("dropdown-service-calendar");
const svcCatSel = document.getElementById("dropdown-service-category");

async function openServiceCreate() {
  // clear edit state
  editingServiceId = null;

  // toggle buttons for CREATE
  const saveBtn   = document.getElementById("save-service-button");
  const updateBtn = document.getElementById("update-service-button");
  const deleteBtn = document.getElementById("delete-service-button");
  if (saveBtn)   saveBtn.style.display   = "inline-block";
  if (updateBtn) updateBtn.style.display = "none";
  if (deleteBtn) deleteBtn.style.display = "none";

  // reset form + image preview
  const form = document.getElementById("add-service-form"); // <-- correct id
  if (form) form.reset();
  const img  = document.getElementById("current-service-image");
  const none = document.getElementById("no-service-image-text");
  const file = document.getElementById("popup-service-image-input");
  if (img)  img.style.display = "none";
  if (none) none.style.display = "block";
  if (file) file.value = "";

  // local refs to selects
  const svcBizSel = document.getElementById("dropdown-service-business");
  const svcCalSel = document.getElementById("dropdown-service-calendar");

  // 1) Businesses (preselect current)
  await loadBusinessOptions("dropdown-service-business");
  const selectedBiz =
    document.getElementById("business-dropdown")?.value ||
    sessionStorage.getItem("selectedBusinessId") || "";
  if (selectedBiz && svcBizSel?.querySelector(`option[value="${selectedBiz}"]`)) {
    svcBizSel.value = selectedBiz;
  }

  // 2) Calendars for that business
  await loadCalendarOptions("dropdown-service-calendar", svcBizSel?.value);

  // 3) Categories for business + selected calendar
  await loadCategoryOptions(
    "dropdown-service-category",
    svcBizSel?.value,
    document.getElementById("dropdown-service-calendar")?.value
  );

  // 4) Open popup
  const servicePopup = document.getElementById("popup-add-service");
  const overlay      = document.getElementById("popup-overlay");
  if (servicePopup && overlay) {
    servicePopup.style.display = "block";
    overlay.style.display = "block";
    document.body.classList.add("popup-open");
  }
}


// bind open button once
if (openServiceBtn && !openServiceBtn.dataset.bound) {
  openServiceBtn.addEventListener("click", openServiceCreate);
  openServiceBtn.dataset.bound = "1";
}

// when Business changes, refresh calendars and categories
if (svcBizSel && !svcBizSel.dataset.bound) {
  svcBizSel.addEventListener("change", async () => {
    await loadCalendarOptions("dropdown-service-calendar", svcBizSel.value);
    await loadCategoryOptions("dropdown-service-category", svcBizSel.value, svcCalSel.value);
  });
  svcBizSel.dataset.bound = "1";
}

// when Calendar changes, refresh categories
if (svcCalSel && !svcCalSel.dataset.bound) {
  svcCalSel.addEventListener("change", async () => {
    await loadCategoryOptions("dropdown-service-category", svcBizSel.value, svcCalSel.value);
  });
  svcCalSel.dataset.bound = "1";
}


//Save Service
// ===== Save Service =====
const serviceForm   = document.getElementById("add-service-form");
const saveServiceBtn = document.getElementById("save-service-button");

if (serviceForm && !serviceForm.dataset.bound) {
  serviceForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const bizSel   = document.getElementById("dropdown-service-business");
    const calSel   = document.getElementById("dropdown-service-calendar");
    const catSel   = document.getElementById("dropdown-service-category");
    const nameIn   = document.getElementById("popup-service-name-input");
    const priceIn  = document.getElementById("popup-service-price-input");
    const descIn   = document.getElementById("popup-service-description-input");
    const durSel   = document.getElementById("dropdown-duration");
    const imgInput = document.getElementById("popup-service-image-input");
    const visChk   = document.getElementById("popup-service-visible-toggle");

    const businessId = bizSel?.value || "";
    const calendarId = calSel?.value || "";
    const categoryId = catSel?.value || "";
    const serviceName = nameIn?.value.trim() || "";
    const price = priceIn?.value ?? "";
    const durationMinutes = durSel?.value || "";

    // Basic validation
    if (!businessId)   return alert("Please choose a business.");
    if (!calendarId)   return alert("Please choose a calendar.");
    if (!categoryId)   return alert("Please choose a category.");
    if (!serviceName)  return alert("Please enter a service name.");
    if (!price)        return alert("Please enter a price.");
    if (!durationMinutes) return alert("Please choose a duration.");

    // Button state
    const prevText = saveServiceBtn?.textContent;
    if (saveServiceBtn) {
      saveServiceBtn.disabled = true;
      saveServiceBtn.textContent = "Saving…";
    }

    try {
      // 1) Optional image upload
      let imageUrl = "";
      const file = imgInput?.files?.[0];
      if (file) {
        const fd = new FormData();
        // server expects the key "file" (upload.single('file'))
        fd.append("file", file);

        const up = await fetch("/api/upload", {
          method: "POST",
          credentials: "include",
          body: fd
        });
        if (!up.ok) {
          let msg = `HTTP ${up.status}`;
          try {
            const err = await up.json();
            if (err?.error) msg += ` - ${err.error}`;
          } catch {}
          throw new Error(`Image upload failed: ${msg}`);
        }
        const upJson = await up.json();
        imageUrl = upJson?.url || "";
      }

      // 2) Create the Service
      const TYPE = "Service"; // must match your Data Type name
      const values = {
        businessId,
        calendarId,
        categoryId,
        serviceName,                             // or "name" if that's your field
        price: parseFloat(price),                // store as number
        description: descIn?.value.trim() || "",
        durationMinutes: parseInt(durationMinutes, 10),
        visible: !!(visChk && visChk.checked),
        imageUrl                                  // optional
      };

      const res = await fetch(`/api/records/${encodeURIComponent(TYPE)}`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ values })
      });
      if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try {
          const err = await res.json();
          if (err?.error) msg += ` - ${err.error}`;
        } catch {}
        throw new Error(msg);
      }

      const created = await res.json();
      console.log("Service created:", created);

      alert("Service saved!");
      serviceForm.reset();

      // Refresh UI
      await loadServiceFilterDropdown();
      await loadServiceList();
      closeAddServicePopup();

    } catch (e) {
      console.error(e);
      alert("Error saving service: " + e.message);
    } finally {
      if (saveServiceBtn) {
        saveServiceBtn.disabled = false;
        saveServiceBtn.textContent = prevText || "Save Service";
      }
    }
  });

  serviceForm.dataset.bound = "1";
}
const svcImgInput = document.getElementById("popup-service-image-input");
if (svcImgInput && !svcImgInput.dataset.bound) {
  svcImgInput.addEventListener("change", () => {
    const file = svcImgInput.files?.[0];
    const img  = document.getElementById("current-service-image");
    const none = document.getElementById("no-service-image-text");
    if (file && img) {
      img.src = URL.createObjectURL(file);
      img.style.display = "block";
      if (none) none.style.display = "none";
    } else {
      if (img) img.style.display = "none";
      if (none) none.style.display = "block";
    }
  });
  svcImgInput.dataset.bound = "1";
}


 ////////////////////////////////////////////////////////////////////
                    //Booking-Page Section                

// ---- Booking-Page Template Picker (no DOMContentLoaded wrapper) ----
// ---- Booking-Page Template Picker ----
function initTemplatePicker() {
  const $select  = document.getElementById('template-select');
  const $preview = document.getElementById('template-preview');
  const $saveBtn = document.getElementById('save-template-btn');
  const $status  = document.getElementById('template-save-status');
  if (!$select || !$preview || !$saveBtn || !$status) return;

  // Keys MUST match TEMPLATE_REGISTRY in template-loader.js
  const PREVIEWS = {
    'basic-hero': `
      <div style="display:grid; gap:8px">
        <div style="background:#f5f5f5; height:120px; display:flex; align-items:center; justify-content:center;">Hero image area</div>
        <div style="background:#fafafa; padding:8px;">Booking flow appears below as usual.</div>
      </div>
    `,
    'spotlight': `
      <div style="display:grid; gap:8px">
        <div style="background:#111; color:#fff; padding:12px;">Logo / Brand Header</div>
        <div style="background:#fafafa; padding:8px;">Booking flow appears below as usual.</div>
      </div>
    `,
    'showcase': `
      <div style="display:grid; grid-template-columns:220px 1fr; gap:12px;">
        <aside style="background:#f9f9f9; height:160px; display:flex; align-items:center; justify-content:center;">Sidebar (images, links)</aside>
        <main style="background:#fafafa; padding:8px;">Booking flow appears on the right.</main>
      </div>
    `,
    'drag-and-drop': `
      <div style="display:grid; gap:8px">
        <div style="background:#111; color:#fff; padding:12px;">Logo / Brand Header</div>
        <div style="background:#fafafa; padding:8px;">Booking flow appears below as usual.</div>
      </div>
    `,
  };

  function showToast(msg) {
    const el = document.createElement('div');
    el.textContent = msg;
    Object.assign(el.style, {
      position: 'fixed', bottom: '16px', right: '16px',
      padding: '10px 14px', background: '#111', color: '#fff',
      borderRadius: '8px', boxShadow: '0 6px 20px rgba(0,0,0,.15)',
      zIndex: 9999, opacity: 0, transition: 'opacity .2s ease'
    });
    document.body.appendChild(el);
    requestAnimationFrame(() => el.style.opacity = 1);
    setTimeout(() => { el.style.opacity = 0; setTimeout(() => el.remove(), 250); }, 1500);
  }

  function renderPreview(val) {
    $preview.innerHTML = PREVIEWS[val] || '<em>No preview.</em>';
  }

  $select.addEventListener('change', e => renderPreview(e.target.value));

  async function loadTemplateSelection() {
    const id = getCurrentBusinessId?.();
    if (!id) { renderPreview($select.value || 'basic-hero'); return; }
    try {
      const r = await fetch(`/api/records/Business/${id}`, { credentials: 'include' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const rec = await r.json();
      const saved = rec?.values?.template || 'basic-hero';
      $select.value = saved;
      renderPreview(saved);
    } catch (e) {
      console.warn('Could not load template:', e);
      renderPreview($select.value || 'basic-hero');
    }
  }
  window.loadTemplateSelection = loadTemplateSelection;

  async function saveTemplate() {
    const id = getCurrentBusinessId?.();
    if (!id) { alert('Select a business first'); return; }
    $saveBtn.disabled = true;
    $status.textContent = 'Saving...';
    try {
      // Also clear any custom page selection so the template is used
      const r = await fetch(`/api/records/Business/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type':'application/json' },
        credentials: 'include',
        body: JSON.stringify({ values: { template: $select.value, selectedBookingPageId: '' } })
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      $status.textContent = 'Saved ✓';
      showToast('Template saved');
    } catch (e) {
      console.error(e);
      $status.textContent = 'Error saving';
      alert('Could not save template. Check the console for details.');
    } finally {
      setTimeout(() => ($status.textContent = ''), 1500);
      $saveBtn.disabled = false;
    }
  }

  $saveBtn.addEventListener('click', saveTemplate);

  // initial paint
  renderPreview($select.value || 'basic-hero');
  loadTemplateSelection();
}


//Show Saved Custom Page 
// ---------- record helpers ----------
const toStr = v => (v == null ? '' : String(v));

function firstKeyLike(obj, regexArr){
  if (!obj) return null;
  const keys = Object.keys(obj);
  for (const rx of regexArr) {
    const k = keys.find(k => rx.test(k));
    if (k) return k;
  }
  return null;
}

function pickPublishedFlag(values){
  // matches "is Published", "is_published", "published" (case-insensitive)
  const key = firstKeyLike(values, [/^is[\s_]*published$/i, /^published$/i]);
  return key ? !!values[key] : false;
}

function pickTime(values){
  const k = firstKeyLike(values, [/^updated\s*at$/i, /^published\s*at$/i, /^created\s*at$/i, /^updated$/i]);
  return k ? (Date.parse(values[k]) || 0) : 0;
}
// Handles "Loading…", nested {value:{_id}} etc.
const BAD_PLACEHOLDERS = new Set(['Loading…','loading…','Loading...','loading...']);

function deepId(x){
  if (!x) return '';
  if (typeof x === 'string') return BAD_PLACEHOLDERS.has(x) ? '' : x;
  if (typeof x === 'object'){
    // Try common keys, then recurse
    const candidates = [x._id, x.id, x.recordId, x.value];
    for (const c of candidates){
      const got = deepId(c);
      if (got) return got;
    }
  }
  return '';
}

// extract a usable business id from a record's values
function extractBusinessId(values){
  const v = values || {};
  const bizK = firstKeyLike(v, [/^business$/i, /businessId/i, /owner/i]);
  const fromRef = bizK ? deepId(v[bizK]) : '';
  return fromRef || toStr(v.businessId) || toStr(v.ownerId) || '';
}

function recordMatchesBusiness(rec, businessId){
  const pageBizId = extractBusinessId(rec?.values);
  return pageBizId && String(pageBizId) === String(businessId);
}

// extract a usable business id from a record's values
function extractBusinessId(values){
  const v = values || {};
  const bizK = firstKeyLike(v, [/^business$/i, /businessId/i, /owner/i]);
  const fromRef = bizK ? deepId(v[bizK]) : '';
  return fromRef || toStr(v.businessId) || toStr(v.ownerId) || '';
}
function recordMatchesBusiness(rec, businessId){
  const pageBizId = extractBusinessId(rec?.values);
  return pageBizId && String(pageBizId) === String(businessId);
}


async function loadPublishedPagesForBusiness(businessId){
  const url = `/api/records/CustomBookingPage?ts=${Date.now()}`;
  const res = await fetch(url, { credentials:'include', headers:{Accept:'application/json'}, cache:'no-store' });
  if (!res.ok) throw new Error(`GET CustomBookingPage ${res.status}`);
  const all = (await res.json()).filter(r => !r.deletedAt);

  // Filter by this business and published
  const pages = all
    .filter(r => recordMatchesBusiness(r, businessId))
    .filter(r => pickPublishedFlag(r.values || {}))
    .sort((a,b) => pickTime(b.values||{}) - pickTime(a.values||{}));

  // Debug once if empty:
  if (!pages.length) {
    console.log('[custom-pages] none for business', businessId, {
      all: all.length,
      sample: all.slice(0,5).map(p => ({
        id: p._id,
        biz: extractBusinessId(p.values),
        isPublished: pickPublishedFlag(p.values||{}),
        title: p.values?.Title
      }))
    });
  }
  return pages;
}

async function getBusinessById(businessId){
  const url = `/api/records/Business?ts=${Date.now()}`;
  const res = await fetch(url, { credentials:'include', headers:{Accept:'application/json'}, cache:'no-store' });
  const list = (await res.json()).filter(r => !r.deletedAt);
  return list.find(r => r._id === businessId) || null;
}

async function patchBusinessValues(businessId, partialValues){
  const res = await fetch(`/api/records/Business/${encodeURIComponent(businessId)}`, {
    method: 'PATCH',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ values: partialValues })
  });
  if (!res.ok) throw new Error(`PATCH Business ${res.status}`);
  return res.json();
}

// Enable/disable template UI when using a custom page
function toggleTemplateArea(usingCustom){
  const tSel = document.getElementById('template-select');
  const tBtn = document.getElementById('save-template-btn');
  const preview = document.getElementById('template-preview');
  [tSel, tBtn].forEach(n => { if (n) n.disabled = !!usingCustom; });
  if (preview) preview.style.opacity = usingCustom ? 0.5 : 1;
}

async function refreshCustomPageControls(businessId){
  const sel = document.getElementById('custom-page-select');
  if (!sel) return;

  sel.innerHTML = '';
  sel.append(new Option('— Use a template (below) —', ''));

  if (!businessId) { toggleTemplateArea(false); return; }

  // pages is declared **here**
  const pages = await loadPublishedPagesForBusiness(businessId);

  // build labels with a safe fallback
  function pickTitle(values, id){
    const key = firstKeyLike(values || {}, [/^title$/i, /^name$/i, /^page\s*title$/i, /^label$/i]);
    const t = key ? String(values[key] ?? '').trim() : '';
    return t || `Page ${String(id).slice(-6)}`;
  }

  if (!pages.length) {
    sel.append(new Option('No published custom pages for this business', ''));
  } else {
    pages.forEach(p => {
      const label = pickTitle(p.values, p._id);
      const opt = new Option(label, String(p._id));
      const when = p.values?.['Published At'] || p.values?.['Updated At'] || p.values?.['Created At'];
      if (when) opt.title = new Date(when).toLocaleString();
      sel.append(opt);
    });
  }

  const biz = await getBusinessById(businessId);
  const selectedId = biz?.values?.selectedBookingPageId || '';
  sel.value = selectedId;
  toggleTemplateArea(!!selectedId);
}


// Save selection
async function saveCustomPageSelection(){
  const businessId = document.getElementById('business-dropdown')?.value || '';
  const sel = document.getElementById('custom-page-select');
  const status = document.getElementById('custom-page-status');
  if (!businessId || !sel) return;

  const selectedId = sel.value; // '' or pageId
  try {
    await patchBusinessValues(businessId, {
      selectedBookingPageId: selectedId   // set or clear
    });
    if (status) status.textContent = 'Saved!';
    toggleTemplateArea(!!selectedId);
    setTimeout(() => { if (status) status.textContent = ''; }, 1500);
  } catch (e){
    console.error(e);
    if (status) status.textContent = 'Save failed';
  }
}

// Events
document.getElementById('save-custom-page-btn')?.addEventListener('click', saveCustomPageSelection);

document.getElementById('business-dropdown')?.addEventListener('change', (e) => {
  refreshCustomPageControls(e.target.value || '');
});

document.addEventListener('DOMContentLoaded', () => {
  const pre = document.getElementById('business-dropdown')?.value || '';
  if (pre) refreshCustomPageControls(pre);
});

}); ////////////////////////////////////////end DOMContentLoaded







////////////////////////////////////////////////////
// ✅ CLOSE LOGIN POPUP
function closeLoginPopup() {
  document.getElementById("popup-login").style.display = "none";
  document.getElementById("popup-overlay").style.display = "none";
  document.body.classList.remove("popup-open");
}

/////////////////////////////////////////////
//Helper 
// Use this everywhere to read the current business id safely
function getCurrentBusinessId() {
  return (
    window.currentBusinessId ||
    document.getElementById('business-dropdown')?.value ||
    sessionStorage.getItem('selectedBusinessId') ||
    null
  );
}

                //End Menu Section 

 //Close All Popups 
function closeAllPopups() {
  // hide all popups that use this shared class
  document.querySelectorAll(".popup-add-business").forEach(el => {
    el.style.display = "none";
  });

  // also hide login if it’s a different markup
  const login = document.getElementById("popup-login");
  if (login) login.style.display = "none";

  const overlay = document.getElementById("popup-overlay");
  if (overlay) overlay.style.display = "none";
  document.body.classList.remove("popup-open");
}


function closeLoginPopup()       { closeAllPopups(); }
function closeAddBusinessPopup() { closeAllPopups(); }
function closeAddCalendarPopup() { closeAllPopups(); }
function closeCategoryPopup() { closeAllPopups(); }
function closeAddServicePopup() { closeAllPopups(); }

async function loadBusinessDropdown({ preserve = true, selectId = null } = {}) {
  const dropdown = document.getElementById("business-dropdown");
  const header   = document.getElementById("selected-business-name");
  if (!dropdown) return;

  if (!dropdown.dataset.bound) {
    dropdown.addEventListener("change", () => {
      const selectedOption = dropdown.options[dropdown.selectedIndex];

      // 1) set current business id globally
      window.currentBusinessId = selectedOption?.value || null;

      // 2) update UI header
      header.textContent = window.currentBusinessId
        ? selectedOption.textContent
        : "Choose business to manage";

      // 3) persist selection for refresh
      sessionStorage.setItem("selectedBusinessId", window.currentBusinessId || "");

      // 4) refresh other dependent sections you already have
      if (typeof loadCalendarList === "function") loadCalendarList();

      // 5) refresh the Template picker for this business
      if (typeof window.loadTemplateSelection === "function") {
        window.loadTemplateSelection();
      }
    });
    dropdown.dataset.bound = "1";
  }

  dropdown.innerHTML = '<option value="">Loading…</option>';
  dropdown.disabled = true;

  try {
    // cache-busting + no-store + soft-delete filter
    const res = await fetch(`/api/records/Business?ts=${Date.now()}`, {
      credentials: 'include',
      cache: 'no-store'
    });
    if (!res.ok) {
      dropdown.innerHTML = '<option value="">-- Choose Business --</option>';
      return;
    }

    const businesses = (await res.json()).filter(b => !b.deletedAt);

    dropdown.innerHTML = '<option value="">-- Choose Business --</option>';
    businesses.forEach(biz => {
      const label =
        biz?.values?.Name ??
        biz?.values?.businessName ??
        "Untitled";
      const opt = document.createElement("option");
      opt.value = biz._id;
      opt.textContent = label;
      dropdown.appendChild(opt);
    });

    // Prefer a specific ID, else restore previous
    if (selectId && dropdown.querySelector(`option[value="${selectId}"]`)) {
      dropdown.value = selectId;
    } else if (preserve) {
      const saved = sessionStorage.getItem("selectedBusinessId");
      if (saved && dropdown.querySelector(`option[value="${saved}"]`)) {
        dropdown.value = saved;
      }
    }

    const selectedOption = dropdown.options[dropdown.selectedIndex];

    // set global + header on first load/restore
    window.currentBusinessId = selectedOption?.value || null;
    header.textContent = window.currentBusinessId
      ? selectedOption.textContent
      : "Choose business to manage";

    // trigger dependent loaders on first load/restore
    if (typeof loadCalendarList === "function") loadCalendarList();
    if (typeof window.loadTemplateSelection === "function") {
      window.loadTemplateSelection();
    }

  } catch (err) {
    console.error("Error loading businesses:", err);
    dropdown.innerHTML = '<option value="">-- Choose Business --</option>';
  } finally {
    dropdown.disabled = false;
  }
}


/////////////////////////////////////////////
                //End Business Section 
// ✅ CLOSE BUSINESS POPUP
function closeAddBusinessPopup() {
  const popup = document.getElementById("popup-add-business");
  const overlay = document.getElementById("popup-overlay");
  if (popup) popup.style.display = "none";
  if (overlay) overlay.style.display = "none";
  document.body.classList.remove("popup-open");
}

// Create-mode opener (only define once; DOM code will bind the button to this)
function openBusinessCreate() {
  const popup   = document.getElementById("popup-add-business");
  const overlay = document.getElementById("popup-overlay");
  const form    = document.getElementById("popup-add-business-form");

  editingBusinessId = null;
  if (form) form.reset();

  // clear preview
   const img = document.getElementById("current-hero-image");
  const noImg = document.getElementById("no-image-text");
  if (img) img.style.display = "none";
  if (noImg) noImg.style.display = "block";
  const fileInput = document.getElementById("image-upload");
  if (fileInput) fileInput.value = "";


  // buttons + title
 document.getElementById("save-button").style.display   = "inline-block";
  document.getElementById("update-button").style.display = "none";
  document.getElementById("delete-button").style.display = "none";
  const title = document.getElementById("popup-title");
  if (title) title.textContent = "Business";

  // open
  if (popup) popup.style.display = "block";
  if (overlay) overlay.style.display = "block";
  document.body.classList.add("popup-open");
}



//Load Business Section List with clickable rows 
// ---- REPLACE your whole loadBusinessList with this version ----
async function loadBusinessList() {
  const nameCol    = document.getElementById("business-name-column");
  const svcCol     = document.getElementById("services-column");
  const clientCol  = document.getElementById("clients-column");
  const gotoCol    = document.getElementById("goto-column");

  if (!nameCol || !svcCol || !clientCol || !gotoCol) return;

  nameCol.textContent   = "Loading…";
  svcCol.textContent    = " ";
  clientCol.textContent = " ";
  gotoCol.textContent   = " ";

  try {
    // You already use this endpoint for businesses
    const res = await fetch(`/api/records/Business?ts=${Date.now()}`, {
      credentials: "include",
      cache: "no-store"
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const businesses = (await res.json()).filter(b => !b.deletedAt);

    // clear columns
    nameCol.innerHTML   = "";
    svcCol.innerHTML    = "";
    clientCol.innerHTML = "";
    gotoCol.innerHTML   = "";

    // keep a cache if you use it elsewhere
    window.businessCache?.clear?.();

    if (!businesses.length) {
      nameCol.innerHTML = "<div>No businesses yet</div>";
      return;
    }

    // One row per business across the four columns
    for (const biz of businesses) {
      window.businessCache?.set?.(biz._id, biz);

      // Name column (click to open editor – your existing behavior)
      const nameRow = document.createElement("div");
      nameRow.className  = "biz-row";
      nameRow.dataset.id = biz._id;
      nameRow.textContent = getFirst(biz.values, ["businessName","name","Business Name"]) || "(Untitled)";
      nameRow.style.cursor = "pointer";
      nameCol.appendChild(nameRow);

      // Services count (placeholder while loading)
      const svcRow = document.createElement("div");
      svcRow.className = "biz-row";
      svcRow.textContent = "…";
      svcCol.appendChild(svcRow);
      // load async
      fillServiceCount(biz._id, svcRow).catch(() => (svcRow.textContent = "0"));

      // Clients count (placeholder while loading)
      const clientRow = document.createElement("div");
      clientRow.className = "biz-row";
      clientRow.textContent = "…";
      clientCol.appendChild(clientRow);
      // load async
      fillClientCount(biz._id, clientRow).catch(() => (clientRow.textContent = "0"));

      // Go To (booking page)
      const gotoRow = document.createElement("div");
      gotoRow.className = "biz-row";
      const slug = slugForBiz(biz);
      const a = document.createElement("a");
      a.href = `/${encodeURIComponent(slug)}`;
      a.textContent = "Open";
      a.target = "_blank"; // optional
      gotoRow.appendChild(a);
      gotoCol.appendChild(gotoRow);
    }

    // Click handler for name column (open editor)
    if (!nameCol.dataset.bound) {
      nameCol.addEventListener("click", (e) => {
        const row = e.target.closest(".biz-row");
        if (!row) return;
        const biz = window.businessCache?.get?.(row.dataset.id);
        if (biz) openBusinessEdit(biz);
      });
      nameCol.dataset.bound = "1";
    }
  } catch (err) {
    console.error("Error loading businesses:", err);
    nameCol.innerHTML = "<div>Error loading list</div>";
  }
}

 //helpers
 // Generic "first non-empty value" from an object by label variants
function getFirst(obj = {}, keys = []) {
  for (const k of keys) {
    if (obj[k] !== undefined && obj[k] !== null && obj[k] !== "") return obj[k];
  }
  return "";
}

// Extract an id from a string or { _id } or { id }
function refId(v) {
  if (!v) return "";
  if (typeof v === "string") return v;
  if (typeof v === "object") {
    return v._id || v.id || v.value || v.$id || "";
  }
  return "";
}
// Build a slug from a Business record
function slugForBiz(biz) {
  const v = biz?.values || {};
  return (
    getFirst(v, ["slug","businessSlug","Slug","bookingSlug"]) ||
    getFirst(v, ["businessName","name","Business Name"])?.toString().trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") ||
    String(biz?._id || "")
  );
}

// Public list fetch (server’s /public/records supports these types without createdBy filter)
async function publicList(dataType, filters = {}, limit = 500) {
  const params = new URLSearchParams({ dataType, limit: String(limit) });
  for (const [k,v] of Object.entries(filters)) {
    if (v !== undefined && v !== null && v !== "") params.append(k, v);
  }
  const r = await fetch(`/public/records?${params.toString()}`, {
    headers: { Accept: "application/json" },
    credentials: "same-origin",
    cache: "no-store"
  });
  if (!r.ok) return [];
  const rows = await r.json();
  return Array.isArray(rows) ? rows : [];
}
// Count services for a business
// --- helper: does this record belong to the given business? ---
function sameBusiness(v, bizId) {
  const candidates = [
    v.Business, v["Business"], v["Business Id"], v["BusinessID"],
    v.business, v.businessId, v.BusinessId
  ].map(refId).filter(Boolean);
  return candidates.some(id => String(id) === String(bizId));
}
function isCanceledAppt(v) {
  const flags = [v["is Canceled"], v.isCanceled, v.canceled, v["Canceled"], v["Cancelled"]];
  if (flags.some(x => x === true || x === "true" || x === 1)) return true;
  const status = (v["Appointment Status"] || v["Status"] || v.status || "").toString().toLowerCase();
  return ["canceled","cancelled","void","no show","no-show"].includes(status);
}

// --- REPLACE THIS: robust unique clients count from appointments ---
async function fillClientCount(businessId, targetEl) {
  try {
    // 1) Try filtered query (fast path if your /public/records normalizer maps Business)
    let appts = await publicList("Appointment", { Business: businessId });

    // 2) If nothing, fetch-all and filter client-side across many aliases
    if (!appts.length) {
      appts = await publicList("Appointment");
    }

    const uniq = new Set();

    const addClient = (val, v) => {
      if (Array.isArray(val)) {
        val.forEach(x => addClient(x, v));
        return;
      }
      const id = refId(val);
      if (id) {
        uniq.add(String(id));
        return;
      }
      // Fallback: identify client by email if there is no id stored
      const email = v["Client Email"] || v.clientEmail || v.Email || v.email;
      if (email) uniq.add(`email:${String(email).toLowerCase()}`);
    };

    for (const r of appts) {
      const v = r.values || r;
      if (!sameBusiness(v, businessId)) continue;
      if (isCanceledAppt(v)) continue;

      // Look for client in many common fields
      const candidates = [
        v.Client, v.client, v["Client Id"], v["Client ID"], v.clientId, v.clientID,
        v["Client(s)"], v["Clients"], v.clients,
        v.User, v.user, v.userId, v["User Id"], v["UserID"],
        v.Customer, v.customer, v.customerId, v["Customer Id"]
      ].filter(x => x != null);

      if (candidates.length) {
        candidates.forEach(cv => addClient(cv, v));
      } else {
        // final fallback by email
        const email = v["Client Email"] || v.clientEmail || v.Email || v.email;
        if (email) uniq.add(`email:${String(email).toLowerCase()}`);
      }
    }

    targetEl.textContent = String(uniq.size);

    // (Optional) quick debug of one sample so you can see real keys in console
    const sample = appts.find(r => sameBusiness(r.values || r, businessId));
    if (sample) {
      const sv = sample.values || sample;
      console.debug("[client-count sample]", {
        client: sv.Client ?? sv.client ?? sv["Client(s)"] ?? sv.User ?? sv.Customer,
        clientEmail: sv["Client Email"] ?? sv.clientEmail ?? sv.Email ?? sv.email
      });
    }
  } catch (e) {
    console.warn("fillClientCount failed:", e);
    targetEl.textContent = "0";
  }
}

// --- robust service count ---
async function fillServiceCount(businessId, targetEl) {
  try {
    // 1) Try filtered query first (fast path if your server normalizes "Business")
    let rows = await publicList("Service", { Business: businessId });
    if (!rows.length) {
      // 2) Fallback: fetch-all and filter by multiple possible keys
      rows = await publicList("Service");
      rows = rows.filter(r => sameBusiness(r.values || r, businessId));
    }
    targetEl.textContent = String(rows.length);

    // (optional) debug one example to verify schema
    if (rows[0]) {
      const v = rows[0].values || rows[0];
      console.debug("[services sample]", {
        business: v.Business || v["Business Id"] || v.businessId,
        name: v["Service Name"] || v.Name || v.name
      });
    }
  } catch (e) {
    console.warn("fillServiceCount failed:", e);
    targetEl.textContent = "0";
  }
}



//Open Business in Edit Mode 
function openBusinessEdit(biz) {
  const popup   = document.getElementById("popup-add-business");
  const overlay = document.getElementById("popup-overlay");


  // store which one we’re editing
  editingBusinessId = biz._id;

  // fill the form
  document.getElementById("popup-business-name-input").value          = biz?.values?.businessName || "";
  document.getElementById("popup-your-name-input").value              = biz?.values?.yourName || "";
  document.getElementById("popup-business-phone-number-input").value  = biz?.values?.phoneNumber || "";
  document.getElementById("popup-business-location-name-input").value = biz?.values?.locationName || "";
  document.getElementById("popup-business-address-input").value       = biz?.values?.businessAddress || "";
  document.getElementById("popup-business-email-input").value         = biz?.values?.businessEmail || "";

  // image preview (optional)
  const img = document.getElementById("current-hero-image");
  const noImg = document.getElementById("no-image-text");
  if (img) {
    const url = biz?.values?.heroImageUrl || "";
    img.src = url;
    img.style.display = url ? "block" : "none";
    if (noImg) noImg.style.display = url ? "none" : "block";
  }
  const fileInput = document.getElementById("image-upload");
  if (fileInput) fileInput.value = "";


  // toggle buttons + title
   document.getElementById("save-button").style.display   = "none";
  document.getElementById("update-button").style.display = "inline-block";
  document.getElementById("delete-button").style.display = "inline-block";
  const title = document.getElementById("popup-title");
  if (title) title.textContent = "Edit Business";

  // open popup
  if (popup) popup.style.display = "block";
  if (overlay) overlay.style.display = "block";
  document.body.classList.add("popup-open");
}














/////////////////////////////////////////////
                //End Calendar Section 

//Load Businesses in Calendar dropdown 
async function loadCalendarBusinessOptions() {
  const sel = document.getElementById("dropdown-calendar-business");
  if (!sel) return;

  sel.innerHTML = '<option value="">Loading…</option>';
  sel.disabled = true;

  let list = []; // <-- always defined
  try {
    const res = await fetch(`/api/records/Business?ts=${Date.now()}`, {
      credentials: 'include',
      cache: 'no-store'
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    list = (await res.json()).filter(b => !b.deletedAt);
  } catch (e) {
    console.error("loadCalendarBusinessOptions:", e);
    // fall through; list stays []
  }

  // Render options from list (even if empty)
  sel.innerHTML = '<option value="">-- Select --</option>';
  for (const biz of list) {
    const label =
      biz?.values?.businessName ??
      biz?.values?.Name ??
      "(Untitled)";
    const opt = document.createElement("option");
    opt.value = biz._id;
    opt.textContent = label;
    sel.appendChild(opt);
  }

  // Prefer the main dropdown's current selection, else session
  const preferred =
    document.getElementById('business-dropdown')?.value ||
    sessionStorage.getItem('selectedBusinessId');

  if (preferred && sel.querySelector(`option[value="${preferred}"]`)) {
    sel.value = preferred;
  }

  sel.disabled = false;
}

// Load Calendars in Calendar Section (with Default radio + server PATCH)
async function loadCalendarList() {
  const nameCol    = document.getElementById("calendar-name-column");
  const defaultCol = document.getElementById("calendar-default-column");
  if (!nameCol || !defaultCol) return;

  // tiny helpers
  const refId = (v) => {
    if (!v) return "";
    if (typeof v === "object") return String(v._id || v.id || "");
    return String(v);
  };
  const getBizId = (row) => {
    const v = row?.values || {};
    return (
      refId(v.Business) ||
      String(v.businessId || v["Business Id"] || "")
    );
  };

  // cache (once)
  if (!window.calendarCache) window.calendarCache = new Map();

  nameCol.textContent = "Loading…";
  defaultCol.innerHTML = "";

  // which business are we looking at?
  const dropdown = document.getElementById("business-dropdown");
  const selectedBusinessId =
    (dropdown && dropdown.value) ||
    sessionStorage.getItem("selectedBusinessId") ||
    "";

  if (!selectedBusinessId) {
    nameCol.innerHTML = "<div>Select a business</div>";
    defaultCol.innerHTML = "";
    return;
  }

  try {
    const res = await fetch(`/api/records/Calendar?ts=${Date.now()}`, {
      credentials: "include",
      cache: "no-store",
      headers: { Accept: "application/json" }
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const calendars = (await res.json()).filter(c => !c.deletedAt);

    // filter to this business robustly (Business could be an id or ref object)
    const rows = calendars.filter(c => getBizId(c) === String(selectedBusinessId));

    nameCol.innerHTML = "";
    defaultCol.innerHTML = "";
    window.calendarCache.clear();

    if (!rows.length) {
      nameCol.innerHTML = "<div>No calendars yet</div>";
      return;
    }

    const radioGroupName = `default-${selectedBusinessId}`;

    // render rows
    rows.forEach(row => {
      window.calendarCache.set(row._id, row);
      const v = row.values || {};
      const calName = v.calendarName ?? v.name ?? "(Untitled)";

      // name cell (clickable to edit)
      const nameDiv = document.createElement("div");
      nameDiv.className = "cal-row";
      nameDiv.dataset.id = row._id;
      nameDiv.textContent = calName;
      nameDiv.style.cursor = "pointer";
      nameCol.appendChild(nameDiv);

      // default radio
      const defDiv = document.createElement("div");
      const radio  = document.createElement("input");
      radio.type = "radio";
      radio.name = radioGroupName;
      radio.value = row._id;
      radio.checked = !!(v["is Default"] || v.isDefault || v.default);
      defDiv.appendChild(radio);
      defaultCol.appendChild(defDiv);

      // on change → set this as default, clear others
      radio.addEventListener("change", async () => {
        if (!radio.checked) return;

        // disable all radios while patching
        defaultCol.querySelectorAll(`input[name="${radioGroupName}"]`)
          .forEach(r => (r.disabled = true));

        const thisId = row._id;

        try {
          // 1) set this calendar to default = true
          const setTrue = fetch(`/api/records/Calendar/${encodeURIComponent(thisId)}`, {
            method: "PATCH",
            credentials: "include",
            headers: { "Content-Type": "application/json", Accept: "application/json" },
            body: JSON.stringify({ values: { "is Default": true } })
          }).then(async r => {
            if (!r.ok) throw new Error(`Set default failed: ${r.status} ${await r.text()}`);
          });

          // 2) clear others (same business) to false
          const siblings = rows.filter(r => r._id !== thisId);
          const clearOthers = siblings.map(sib =>
            fetch(`/api/records/Calendar/${encodeURIComponent(sib._id)}`, {
              method: "PATCH",
              credentials: "include",
              headers: { "Content-Type": "application/json", Accept: "application/json" },
              body: JSON.stringify({ values: { "is Default": false } })
            }).then(async r => {
              if (!r.ok) throw new Error(`Clear default failed: ${r.status} ${await r.text()}`);
            })
          );

          await Promise.all([setTrue, ...clearOthers]);

          // update local cache + UI
          rows.forEach(r => {
            const vv = r.values || (r.values = {});
            vv["is Default"] = (r._id === thisId);
          });
          defaultCol.querySelectorAll(`input[name="${radioGroupName}"]`).forEach(inp => {
            inp.checked = (inp.value === String(thisId));
          });
        } catch (err) {
          console.error("Default toggle failed:", err);
          alert("Could not set default calendar. Please try again.");
          // revert UI
          defaultCol.querySelectorAll(`input[name="${radioGroupName}"]`).forEach(inp => {
            const cached = window.calendarCache.get(inp.value);
            const isDef  = !!(cached?.values?.["is Default"] || cached?.values?.isDefault);
            inp.checked = isDef;
          });
        } finally {
          defaultCol.querySelectorAll(`input[name="${radioGroupName}"]`)
            .forEach(r => (r.disabled = false));
        }
      });
    });

    // bind once: click a name to open edit view (if you have it)
    if (!nameCol.dataset.bound) {
      nameCol.addEventListener("click", (e) => {
        const el = e.target.closest(".cal-row");
        if (!el) return;
        const cal = window.calendarCache.get(el.dataset.id);
        if (cal && typeof window.openCalendarEdit === "function") {
          window.openCalendarEdit(cal);
        }
      });
      nameCol.dataset.bound = "1";
    }
  } catch (err) {
    console.error("loadCalendarList:", err);
    nameCol.innerHTML = "<div>Error loading calendars</div>";
  }
}







/////////////////////////////////////////////
                //End Calendar Section 
                
//Reusable get Businesses 
async function loadBusinessOptions(selectId) {
  const sel = document.getElementById(selectId);
  if (!sel) return;

  sel.innerHTML = '<option value="">Loading…</option>';
  sel.disabled = true;

  try {
    const res = await fetch(`/api/records/Business?ts=${Date.now()}`, {
      credentials: 'include',
      cache: 'no-store'
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const businesses = (await res.json()).filter(b => !b.deletedAt);

    sel.innerHTML = '<option value="">-- Select --</option>';
    businesses.forEach(biz => {
      const opt = document.createElement('option');
      opt.value = biz._id;
      opt.textContent = biz?.values?.businessName || biz?.values?.Name || '(Untitled)';
      sel.appendChild(opt);
    });

    // Preselect the main dropdown’s current business (if any)
    const fromMain =
      document.getElementById('business-dropdown')?.value ||
      sessionStorage.getItem('selectedBusinessId');
    if (fromMain && sel.querySelector(`option[value="${fromMain}"]`)) {
      sel.value = fromMain;
    }
  } catch (e) {
    console.error('loadBusinessOptions:', e);
    sel.innerHTML = '<option value="">-- Select --</option>';
  } finally {
    sel.disabled = false;
  }
}


//Reusable get Calendars
async function loadCalendarOptions(selectId, businessId) {
  const sel = document.getElementById(selectId);
  if (!sel) return;

  if (!businessId) {
    sel.innerHTML = '<option value="">-- Select --</option>';
    sel.disabled = true;
    return;
  }

  sel.innerHTML = '<option value="">Loading…</option>';
  sel.disabled = true;

  try {
    const res = await fetch(`/api/records/Calendar?ts=${Date.now()}`, {
      credentials: 'include',
      cache: 'no-store'
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const rows = (await res.json())
      .filter(c => !c.deletedAt && c?.values?.businessId === businessId);

    sel.innerHTML = '<option value="">-- Select --</option>';
    rows.forEach(cal => {
      const label = cal?.values?.calendarName ?? cal?.values?.name ?? '(Untitled)';
      const opt = document.createElement('option');
      opt.value = cal._id;
      opt.textContent = label;
      sel.appendChild(opt);
    });

    sel.disabled = rows.length === 0;
  } catch (e) {
    console.error('loadCalendarOptions:', e);
    sel.innerHTML = '<option value="">-- Select --</option>';
    sel.disabled = true;
  }
}

//Reusable Category
async function loadCategoryOptions(selectId, businessId, calendarId) {
  const sel = document.getElementById(selectId);
  if (!sel) return;

  if (!businessId || !calendarId) {
    sel.innerHTML = '<option value="">-- Select --</option>';
    sel.disabled = true;
    return;
  }

  sel.innerHTML = '<option value="">Loading…</option>';
  sel.disabled = true;

  try {
    const res = await fetch(`/api/records/Category?ts=${Date.now()}`, {
      credentials: 'include',
      cache: 'no-store'
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const rows = (await res.json()).filter(cat =>
      !cat.deletedAt &&
      cat?.values?.businessId === businessId &&
      cat?.values?.calendarId === calendarId
    );

    sel.innerHTML = '<option value="">-- Select --</option>';
    rows.forEach(cat => {
      const label = cat?.values?.categoryName ?? cat?.values?.name ?? '(Untitled)';
      const opt = document.createElement('option');
      opt.value = cat._id;
      opt.textContent = label;
      sel.appendChild(opt);
    });

    sel.disabled = rows.length === 0;
  } catch (e) {
    console.error('loadCategoryOptions:', e);
    sel.innerHTML = '<option value="">-- Select --</option>';
    sel.disabled = true;
  }
}


//Update Calendar 
async function openCalendarEdit(cal) {
  const popup   = document.getElementById("popup-add-calendar");
  const overlay = document.getElementById("popup-overlay");

  editingCalendarId = cal._id;

  // Make sure business dropdown exists and is filled
  await loadCalendarBusinessOptions(); // fills #dropdown-calendar-business

  // Prefill fields
  const bizSel = document.getElementById("dropdown-calendar-business");
  const nameIn = document.getElementById("popup-calendar-name-input");

  if (bizSel) bizSel.value = cal?.values?.businessId || "";
  if (nameIn) nameIn.value = cal?.values?.calendarName ?? cal?.values?.name ?? "";

  // Toggle buttons & title (Edit mode)
  const saveBtn   = document.getElementById("save-calendar-button");
  const updateBtn = document.getElementById("update-calendar-button");
  const deleteBtn = document.getElementById("delete-calendar-button");
  if (saveBtn)   saveBtn.style.display   = "none";
  if (updateBtn) updateBtn.style.display = "inline-block";
  if (deleteBtn) deleteBtn.style.display = "inline-block";

  // Open popup
  if (popup)  popup.style.display = "block";
  if (overlay) overlay.style.display = "block";
  document.body.classList.add("popup-open");
}

// UPDATE handler (bind once inside DOMContentLoaded or here with guard)
(function bindCalendarUpdateDeleteOnce() {
  const updateBtn = document.getElementById("update-calendar-button");
  const deleteBtn = document.getElementById("delete-calendar-button");

  if (updateBtn && !updateBtn.dataset.bound) {
    updateBtn.addEventListener("click", async () => {
      if (!editingCalendarId) return alert("No calendar selected.");

      const TYPE = "Calendar";
      const nameIn = document.getElementById("popup-calendar-name-input");
      const bizSel = document.getElementById("dropdown-calendar-business");

      const calendarName = nameIn?.value.trim() || "";
      const businessId   = bizSel?.value || "";

      if (!calendarName) return alert("Please enter a calendar name.");
      if (!businessId)   return alert("Please choose a business.");

      const prev = updateBtn.textContent;
      updateBtn.disabled = true;
      updateBtn.textContent = "Updating…";

      try {
        const res = await fetch(`/api/records/${encodeURIComponent(TYPE)}/${editingCalendarId}`, {
          method: "PATCH",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ values: { calendarName, businessId } })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        await res.json();

        alert("Calendar updated!");
        closeAddCalendarPopup();
        await loadCalendarList();
      } catch (e) {
        console.error(e);
        alert("Error updating calendar: " + e.message);
      } finally {
        updateBtn.disabled = false;
        updateBtn.textContent = prev;
      }
    });
    updateBtn.dataset.bound = "1";
  }

  //Delete Calendar 
  if (deleteBtn && !deleteBtn.dataset.bound) {
    deleteBtn.addEventListener("click", async () => {
      if (!editingCalendarId) return;
      if (!confirm("Delete this calendar? This cannot be undone.")) return;

      const TYPE = "Calendar";
      const prev = deleteBtn.textContent;
      deleteBtn.disabled = true;
      deleteBtn.textContent = "Deleting…";

      try {
        const res = await fetch(`/api/records/${encodeURIComponent(TYPE)}/${editingCalendarId}`, {
          method: "DELETE",
          credentials: "include"
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        alert("Calendar deleted.");
        closeAddCalendarPopup();
        await loadCalendarList();

        // If your Category list depends on calendars, refresh it too (optional):
        // await loadCategoryFilterDropdown();
        // await loadCategoryList();

      } catch (e) {
        console.error(e);
        alert("Error deleting calendar: " + e.message);
      } finally {
        deleteBtn.disabled = false;
        deleteBtn.textContent = prev;
      }
    });
    deleteBtn.dataset.bound = "1";
  }
})();


/////////////////////////////////////////////
                //End Category Section 
       async function loadCategoryFilterDropdown() {
  const wrapper = document.getElementById("calendar-dropdown-wrapper");
  const sel     = document.getElementById("category-calendar-dropdown");
  if (!sel) return;

  const bizDropdown = document.getElementById("business-dropdown");
  const businessId =
    (bizDropdown && bizDropdown.value) ||
    sessionStorage.getItem("selectedBusinessId") || "";

  if (!businessId) {
    if (wrapper) wrapper.style.display = "none";
    sel.innerHTML = '<option value="">-- Choose a Calendar --</option>';
    sel.disabled = true;
    return;
  }

  if (wrapper) wrapper.style.display = "block";
  sel.innerHTML = '<option value="">Loading…</option>';
  sel.disabled = true;

  try {
    const res = await fetch("/api/records/Calendar", { credentials: "include" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const calendars = (await res.json()).filter(c => c?.values?.businessId === businessId);

    sel.innerHTML = '<option value="">All Calendars</option>';
    calendars.forEach(c => {
      const label = c?.values?.calendarName ?? c?.values?.name ?? "(Untitled)";
      const opt = document.createElement("option");
      opt.value = c._id;
      opt.textContent = label;
      sel.appendChild(opt);
    });

    sel.disabled = calendars.length === 0;
  } catch (e) {
    console.error("loadCategoryFilterDropdown:", e);
    sel.innerHTML = '<option value="">-- Choose a Calendar --</option>';
    sel.disabled = true;
  }
}
         
 //Load Category List 
async function loadCategoryList() {
  const nameCol = document.getElementById("category-name-column");
  const calCol  = document.getElementById("category-calendar-column");
  if (!nameCol || !calCol) return;

  nameCol.innerHTML = "Loading…";
  calCol.innerHTML  = "";

  // Business filter (keep this)
  const bizDropdown = document.getElementById("business-dropdown");
  const businessId =
    (bizDropdown && bizDropdown.value) ||
    sessionStorage.getItem("selectedBusinessId") || "";

  if (!businessId) {
    nameCol.innerHTML = "<div>Select a business</div>";
    return;
  }

  // Optional calendar filter
  const filterCalSel = document.getElementById("category-calendar-dropdown");
  const filterCalendarId = filterCalSel ? filterCalSel.value : "";

  try {
    // Fetch once, avoid cache
    const [catRes, calRes] = await Promise.all([
      fetch(`/api/records/Category?ts=${Date.now()}`, { credentials: "include", cache: "no-store" }),
      fetch(`/api/records/Calendar?ts=${Date.now()}`, { credentials: "include", cache: "no-store" })
    ]);
    if (!catRes.ok || !calRes.ok) throw new Error("Fetch failed");

    const [rawCats, rawCals] = await Promise.all([catRes.json(), calRes.json()]);

    // Hide soft-deleted; only calendars for this business
    const categories = rawCats.filter(c => !c.deletedAt);
    const calendars  = rawCals.filter(c => !c.deletedAt && c?.values?.businessId === businessId);

    // Map calendarId -> calendarName
    const calNameById = new Map(
      calendars.map(c => [c._id, c?.values?.calendarName ?? c?.values?.name ?? "(Untitled)"])
    );

    // Filter by business and (optionally) calendar
    const rows = categories.filter(cat => {
      const belongsToBiz  = cat?.values?.businessId === businessId;
      const calendarMatch = !filterCalendarId || cat?.values?.calendarId === filterCalendarId;
      return belongsToBiz && calendarMatch;
    });

    nameCol.innerHTML = "";
    calCol.innerHTML  = "";
    if (window.categoryCache) window.categoryCache.clear?.();

    if (!rows.length) {
      nameCol.innerHTML = "<div>No categories yet</div>";
      return;
    }

    rows.forEach(cat => {
      window.categoryCache?.set(cat._id, cat);

      // Name (clickable → edit)
      const n = document.createElement("div");
      n.className = "cat-row";
      n.dataset.id = cat._id;
      n.style.cursor = "pointer";
      n.textContent = cat?.values?.categoryName ?? cat?.values?.name ?? "(Untitled)";
      nameCol.appendChild(n);

      // Calendar name
      const calName = calNameById.get(cat?.values?.calendarId) || "(Unknown)";
      const c = document.createElement("div");
      c.textContent = calName;
      calCol.appendChild(c);
    });

    // Delegate clicks once → open edit mode
    if (!nameCol.dataset.bound) {
      nameCol.addEventListener("click", (e) => {
        const el = e.target.closest(".cat-row");
        if (!el) return;
        const cat = window.categoryCache?.get(el.dataset.id);
        if (cat) openCategoryEdit(cat);
      });
      nameCol.dataset.bound = "1";
    }

  } catch (e) {
    console.error("loadCategoryList:", e);
    nameCol.innerHTML = "<div>Error loading categories</div>";
  }
}

          
//
function bindCategoryUI() {
  // When Business changes, refresh the Category filter dropdown and list
  const bizDropdown = document.getElementById("business-dropdown");
  if (bizDropdown && !bizDropdown.dataset.catBound) {
    bizDropdown.addEventListener("change", async () => {
      await loadCategoryFilterDropdown();
      await loadCategoryList();
    });
    bizDropdown.dataset.catBound = "1";
  }

  // When Calendar filter changes, refresh the list
  const catFilterSel = document.getElementById("category-calendar-dropdown");
  if (catFilterSel && !catFilterSel.dataset.bound) {
    catFilterSel.addEventListener("change", loadCategoryList);
    catFilterSel.dataset.bound = "1";
  }

  // Initial render (don’t await at top-level; just fire & forget)
  loadCategoryFilterDropdown().then(loadCategoryList);
}

//Open Add Category in Edit mode 
async function openCategoryEdit(cat) {
  const popup   = document.getElementById("popup-add-category");
  const overlay = document.getElementById("popup-overlay");

  editingCategoryId = cat._id;

  // 1) Fill Business dropdown
  await loadBusinessOptions("dropdown-category-business");
  const bizSel = document.getElementById("dropdown-category-business");
  if (bizSel) bizSel.value = cat?.values?.businessId || "";

  // 2) Fill Calendar dropdown for that business
  await loadCalendarOptions("dropdown-business-calendar", bizSel?.value || "");
  const calSel = document.getElementById("dropdown-business-calendar");
  if (calSel) calSel.value = cat?.values?.calendarId || "";

  // 3) Set the name input
  const nameIn = document.getElementById("popup-category-name-input");
  if (nameIn) {
    nameIn.value = cat?.values?.categoryName ?? cat?.values?.name ?? "";
  } else {
    console.warn("Category name input not found: #popup-category-name-input");
  }

  // 4) Toggle buttons (Edit mode)
  const saveBtn   = document.getElementById("save-category-button");
  const updateBtn = document.getElementById("update-category-button");
  const deleteBtn = document.getElementById("delete-category-button");
  if (saveBtn)   saveBtn.style.display   = "none";
  if (updateBtn) updateBtn.style.display = "inline-block";
  if (deleteBtn) deleteBtn.style.display = "inline-block";

  // 5) Open popup
  if (popup)  popup.style.display = "block";
  if (overlay) overlay.style.display = "block";
  document.body.classList.add("popup-open");
}

//Update Category 
(function bindCategoryUpdateDeleteOnce() {
  const updateBtn = document.getElementById("update-category-button");
  const deleteBtn = document.getElementById("delete-category-button");

  if (updateBtn && !updateBtn.dataset.bound) {
    updateBtn.addEventListener("click", async () => {
      if (!editingCategoryId) return alert("No category selected.");

      const TYPE = "Category";
      const nameIn = document.getElementById("popup-category-name-input");
      const bizSel = document.getElementById("dropdown-category-business");
      const calSel = document.getElementById("dropdown-business-calendar");

      const categoryName = nameIn?.value.trim() || "";
      const businessId   = bizSel?.value || "";
      const calendarId   = calSel?.value || "";

      if (!businessId)   return alert("Please choose a business.");
      if (!calendarId)   return alert("Please choose a calendar.");
      if (!categoryName) return alert("Please enter a category name.");

      const prev = updateBtn.textContent;
      updateBtn.disabled = true;
      updateBtn.textContent = "Updating…";

      try {
        const res = await fetch(`/api/records/${encodeURIComponent(TYPE)}/${editingCategoryId}`, {
          method: "PATCH",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ values: { categoryName, businessId, calendarId } })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        await res.json();

        alert("Category updated!");
        closeCategoryPopup();
        await loadCategoryList();
      } catch (e) {
        console.error(e);
        alert("Error updating category: " + e.message);
      } finally {
        updateBtn.disabled = false;
        updateBtn.textContent = prev;
      }
    });
    updateBtn.dataset.bound = "1";
  }

  if (deleteBtn && !deleteBtn.dataset.bound) {
    deleteBtn.addEventListener("click", async () => {
      if (!editingCategoryId) return;
      if (!confirm("Delete this category? This cannot be undone.")) return;

      const TYPE = "Category";
      const prev = deleteBtn.textContent;
      deleteBtn.disabled = true;
      deleteBtn.textContent = "Deleting…";

      try {
        const res = await fetch(`/api/records/${encodeURIComponent(TYPE)}/${editingCategoryId}`, {
          method: "DELETE",
          credentials: "include"
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        alert("Category deleted.");
        closeCategoryPopup();
        await loadCategoryList();
      } catch (e) {
        console.error(e);
        alert("Error deleting category: " + e.message);
      } finally {
        deleteBtn.disabled = false;
        deleteBtn.textContent = prev;
      }
    });
    deleteBtn.dataset.bound = "1";
  }
})();

                  //////////////////////////////////////
                              //End Service Section 




 function formatMoney(val) {
  const num = typeof val === "number" ? val : parseFloat(String(val).replace(/[^\d.-]/g, ""));
  if (!isFinite(num)) return "";
  return new Intl.NumberFormat(undefined, { style: "currency", currency: "USD" }).format(num);
}         

//Fill the list in Service List
async function loadServiceFilterDropdown() {
  const wrapper = document.getElementById("service-section-calendar-dropdown-wrapper");
  const sel     = document.getElementById("service-section-calendar-dropdown");
  if (!sel) return;

  const bizDropdown = document.getElementById("business-dropdown");
  const businessId =
    (bizDropdown && bizDropdown.value) ||
    sessionStorage.getItem("selectedBusinessId") || "";

  if (!businessId) {
    if (wrapper) wrapper.style.display = "none";
    sel.innerHTML = '<option value="">-- Choose a Calendar --</option>';
    sel.disabled = true;
    return;
  }

  if (wrapper) wrapper.style.display = "block";
  sel.innerHTML = '<option value="">Loading…</option>';
  sel.disabled = true;

  try {
    const res = await fetch(`/api/records/Calendar?ts=${Date.now()}`, {
      credentials: "include",
      cache: "no-store"
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const calendars = (await res.json())
      .filter(c => !c.deletedAt && c?.values?.businessId === businessId);

    sel.innerHTML = '<option value="">All Calendars</option>';
    calendars.forEach(c => {
      const label = c?.values?.calendarName ?? c?.values?.name ?? "(Untitled)";
      const opt = document.createElement("option");
      opt.value = c._id;
      opt.textContent = label;
      sel.appendChild(opt);
    });

    sel.disabled = calendars.length === 0;
  } catch (e) {
    console.error("loadServiceFilterDropdown:", e);
    sel.innerHTML = '<option value="">-- Choose a Calendar --</option>';
    sel.disabled = true;
  }
}

async function loadServiceList() {
  const nameCol     = document.getElementById("service-name-column");
  const calCol      = document.getElementById("service-calendar-column");
  const catCol      = document.getElementById("service-category-column");
  const priceCol    = document.getElementById("service-price-column");
  if (!nameCol || !calCol || !catCol || !priceCol) return;

  nameCol.innerHTML  = "Loading…";
  calCol.innerHTML   = "";
  catCol.innerHTML   = "";
  priceCol.innerHTML = "";

  // which business is active?
  const bizDropdown = document.getElementById("business-dropdown");
  const businessId =
    (bizDropdown && bizDropdown.value) ||
    sessionStorage.getItem("selectedBusinessId") || "";

  if (!businessId) {
    nameCol.innerHTML = "<div>Select a business</div>";
    return;
  }

  // optional calendar filter (Service section’s dropdown)
  const filterSel = document.getElementById("service-section-calendar-dropdown");
  const filterCalendarId = filterSel ? filterSel.value : "";

  try {
    // Fetch everything we need once
    const [svcRes, calRes, catRes] = await Promise.all([
      fetch(`/api/records/Service?ts=${Date.now()}`,   { credentials: "include", cache: "no-store" }),
      fetch(`/api/records/Calendar?ts=${Date.now()}`,  { credentials: "include", cache: "no-store" }),
      fetch(`/api/records/Category?ts=${Date.now()}`,  { credentials: "include", cache: "no-store" })
    ]);
    if (!svcRes.ok || !calRes.ok || !catRes.ok) throw new Error("Fetch failed");

    const [rawServices, rawCalendars, rawCategories] = await Promise.all([
      svcRes.json(), calRes.json(), catRes.json()
    ]);

    // Hide soft-deleted + narrow calendars/categories to this business
    const services  = rawServices.filter(s => !s.deletedAt);
    const calendars = rawCalendars.filter(c => !c.deletedAt && c?.values?.businessId === businessId);
    const categories= rawCategories.filter(c => !c.deletedAt && c?.values?.businessId === businessId);

    // Quick lookup maps
    const calNameById = new Map(calendars.map(c => [
      c._id, c?.values?.calendarName ?? c?.values?.name ?? "(Untitled)"
    ]));
    const catNameById = new Map(categories.map(c => [
      c._id, c?.values?.categoryName ?? c?.values?.name ?? "(Untitled)"
    ]));

    // Filter services to business (and calendar if selected)
    const rows = services.filter(s => {
      const belongsToBiz = s?.values?.businessId === businessId;
      const calMatch = !filterCalendarId || s?.values?.calendarId === filterCalendarId;
      return belongsToBiz && calMatch;
    });

    // Render
  // inside loadServiceList(), after you computed `rows`
nameCol.innerHTML  = "";
calCol.innerHTML   = "";
catCol.innerHTML   = "";
priceCol.innerHTML = "";
if (window.serviceCache && typeof window.serviceCache.clear === "function") {
  window.serviceCache.clear();
}


if (!rows.length) {
  nameCol.innerHTML = "<div>No services yet</div>";
  return;
}

rows.forEach(svc => {
  window.serviceCache.set(svc._id, svc);

  const svcName = svc?.values?.serviceName ?? svc?.values?.name ?? "(Untitled)";
  const calName = calNameById.get(svc?.values?.calendarId) || "(Unknown)";
  const catName = catNameById.get(svc?.values?.categoryId) || "(Unassigned)";
 const rawPrice = firstDefined(
  svc?.values?.price,
  svc?.values?.servicePrice,
  svc?.values?.Price,     // capitalized fallback
  svc?.values?.amount,    // extra safety
  svc?.values?.cost
);
const price = rawPrice !== undefined ? formatMoney(rawPrice) : "";

  // Name cell (clickable)
  const n = document.createElement("div");
  n.className = "service-row";
  n.dataset.id = svc._id;
  n.style.cursor = "pointer";
  n.textContent = svcName;
  nameCol.appendChild(n);

  // Calendar cell
  const c1 = document.createElement("div");
  c1.textContent = calName;
  calCol.appendChild(c1);

  // Category cell
  const c2 = document.createElement("div");
  c2.textContent = catName;
  catCol.appendChild(c2);

  // Price cell
  const p = document.createElement("div");
  p.textContent = price || "";
  priceCol.appendChild(p);
});

// one-time delegated click -> edit
if (!nameCol.dataset.bound) {
  nameCol.addEventListener("click", (e) => {
    const row = e.target.closest(".service-row");
    if (!row) return;
    const svc = window.serviceCache.get(row.dataset.id);
    if (svc) openServiceEdit(svc);
  });
  nameCol.dataset.bound = "1";
}

  } catch (e) {
    console.error("loadServiceList:", e);
    nameCol.innerHTML = "<div>Error loading services</div>";
  }
}

//Update Service 
(function bindServiceUpdateDeleteOnce() {
  const updateBtn = document.getElementById("update-service-button");
  const deleteBtn = document.getElementById("delete-service-button");

  // UPDATE
  if (updateBtn && !updateBtn.dataset.bound) {
    updateBtn.addEventListener("click", async () => {
      if (!editingServiceId) return alert("No service selected.");

      const bizSel  = document.getElementById("dropdown-service-business");
      const calSel  = document.getElementById("dropdown-service-calendar");
      const catSel  = document.getElementById("dropdown-service-category");
      const nameIn  = document.getElementById("popup-service-name-input");
      const priceIn = document.getElementById("popup-service-price-input");
      const descIn  = document.getElementById("popup-service-description-input");
      const durSel  = document.getElementById("dropdown-duration");
      const visChk  = document.getElementById("popup-service-visible-toggle");
      const fileIn  = document.getElementById("popup-service-image-input");

      const businessId = bizSel?.value || "";
      const calendarId = calSel?.value || "";
      const categoryId = catSel?.value || "";
      const serviceName = nameIn?.value.trim() || "";
      const price = priceIn?.value ?? "";
      const durationMinutes = durSel?.value || "";

      if (!businessId)   return alert("Please choose a business.");
      if (!calendarId)   return alert("Please choose a calendar.");
      if (!categoryId)   return alert("Please choose a category.");
      if (!serviceName)  return alert("Please enter a service name.");
      if (!price)        return alert("Please enter a price.");
      if (!durationMinutes) return alert("Please choose a duration.");

      updateBtn.disabled = true;
      const prev = updateBtn.textContent;
      updateBtn.textContent = "Updating…";

      try {
        // optional image upload if a new file is chosen
        let imageUrlToSet = undefined;
        const file = fileIn?.files?.[0];
        if (file) {
          const fd = new FormData();
          fd.append("file", file);
          const up = await fetch("/api/upload", { method: "POST", credentials: "include", body: fd });
          if (!up.ok) {
            let msg = `HTTP ${up.status}`;
            try { const j = await up.json(); if (j?.error) msg += ` - ${j.error}`; } catch {}
            throw new Error(`Image upload failed: ${msg}`);
          }
          const j = await up.json();
          imageUrlToSet = j?.url || "";
        }

        // build values (only include imageUrl if we uploaded a new one)
        const values = {
          businessId,
          calendarId,
          categoryId,
          serviceName,
          price: parseFloat(price),
          description: descIn?.value.trim() || "",
          durationMinutes: parseInt(durationMinutes, 10),
          visible: !!(visChk && visChk.checked)
        };
        if (imageUrlToSet !== undefined) values.imageUrl = imageUrlToSet;

        const TYPE = "Service";
        const res = await fetch(`/api/records/${encodeURIComponent(TYPE)}/${editingServiceId}`, {
          method: "PATCH",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ values })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        await res.json();

        alert("Service updated!");
        closeAddServicePopup();
        await loadServiceFilterDropdown();
        await loadServiceList();
      } catch (e) {
        console.error(e);
        alert("Error updating service: " + e.message);
      } finally {
        updateBtn.disabled = false;
        updateBtn.textContent = prev;
      }
    });
    updateBtn.dataset.bound = "1";
  }

  // DELETE Service
  if (deleteBtn && !deleteBtn.dataset.bound) {
    deleteBtn.addEventListener("click", async () => {
      if (!editingServiceId) return;
      if (!confirm("Delete this service? This cannot be undone.")) return;

      deleteBtn.disabled = true;
      const prev = deleteBtn.textContent;
      deleteBtn.textContent = "Deleting…";

      try {
        const TYPE = "Service";
        const res = await fetch(`/api/records/${encodeURIComponent(TYPE)}/${editingServiceId}`, {
          method: "DELETE",
          credentials: "include"
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        alert("Service deleted.");
        closeAddServicePopup();
        await loadServiceFilterDropdown();
        await loadServiceList();
      } catch (e) {
        console.error(e);
        alert("Error deleting service: " + e.message);
      } finally {
        deleteBtn.disabled = false;
        deleteBtn.textContent = prev;
      }
    });
    deleteBtn.dataset.bound = "1";
  }
})();



window.openServiceEdit = async function openServiceEdit(svc) {
  const popup   = document.getElementById("popup-add-service");
  const overlay = document.getElementById("popup-overlay");

  // which service we’re editing
  editingServiceId = svc._id;

  // load dropdowns and preselect
  await loadBusinessOptions("dropdown-service-business");
  const bizSel = document.getElementById("dropdown-service-business");
  if (bizSel) bizSel.value = svc?.values?.businessId || "";

  await loadCalendarOptions("dropdown-service-calendar", bizSel?.value || "");
  const calSel = document.getElementById("dropdown-service-calendar");
  if (calSel) calSel.value = svc?.values?.calendarId || "";

  await loadCategoryOptions("dropdown-service-category", bizSel?.value || "", calSel?.value || "");
  const catSel = document.getElementById("dropdown-service-category");
  if (catSel) catSel.value = svc?.values?.categoryId || "";

  // fill inputs
  const nameIn  = document.getElementById("popup-service-name-input");
  const priceIn = document.getElementById("popup-service-price-input");
  const descIn  = document.getElementById("popup-service-description-input");
  const durSel  = document.getElementById("dropdown-duration");
  const visChk  = document.getElementById("popup-service-visible-toggle");
  const fileIn  = document.getElementById("popup-service-image-input");

  if (nameIn)  nameIn.value  = svc?.values?.serviceName ?? svc?.values?.name ?? "";
  if (priceIn) priceIn.value = svc?.values?.price ?? svc?.values?.servicePrice ?? "";
  if (descIn)  descIn.value  = svc?.values?.description ?? "";
  if (durSel)  durSel.value  = (svc?.values?.durationMinutes ?? "").toString();
  if (visChk)  visChk.checked = !!svc?.values?.visible;
  if (fileIn)  fileIn.value = "";

  // image preview
  const img  = document.getElementById("current-service-image");
  const none = document.getElementById("no-service-image-text");
  const imageUrl = svc?.values?.imageUrl || "";
  if (img) {
    img.src = imageUrl;
    img.style.display = imageUrl ? "block" : "none";
  }
  if (none) none.style.display = imageUrl ? "none" : "block";

  // show Update/Delete; hide Save
  const saveBtn   = document.getElementById("save-service-button");
  const updateBtn = document.getElementById("update-service-button");
  const deleteBtn = document.getElementById("delete-service-button");
  if (saveBtn)   saveBtn.style.display   = "none";
  if (updateBtn) updateBtn.style.display = "inline-block";
  if (deleteBtn) deleteBtn.style.display = "inline-block";

  // open popup
  if (popup && overlay) {
    popup.style.display = "block";
    overlay.style.display = "block";
    document.body.classList.add("popup-open");
  }
};

function bindServiceUI() {
  // When Business changes → refresh filter + list
  const bizDropdown = document.getElementById("business-dropdown");
  if (bizDropdown && !bizDropdown.dataset.svcBound) {
    bizDropdown.addEventListener("change", async () => {
      await loadServiceFilterDropdown();
      await loadServiceList();
    });
    bizDropdown.dataset.svcBound = "1";
  }

  // When Service-section Calendar filter changes → refresh list
  const svcFilterSel = document.getElementById("service-section-calendar-dropdown");
  if (svcFilterSel && !svcFilterSel.dataset.bound) {
    svcFilterSel.addEventListener("change", loadServiceList);
    svcFilterSel.dataset.bound = "1";
  }

  // Initial render
  loadServiceFilterDropdown().then(loadServiceList);
}




