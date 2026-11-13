/**
 * Unified date/time formatting utility for all modules
 * Falls back to current system time for invalid/missing timestamps
 */

const validDate = (ts) => {
  if (!ts) return null;
  const d = new Date(ts);
  return !isNaN(d.getTime()) ? d : null;
};

// Fallback for current date/time with proper format
export const now = () => new Date();

export const fmtTime = (ts) => {
  const d = validDate(ts) || now();
  try {
    return d.toLocaleTimeString("en-GB", { hour12: false });
  } catch {
    return now().toLocaleTimeString("en-GB", { hour12: false });
  }
};

export const fmtDateTime = (ts) => {
  const d = validDate(ts) || now();
  try {
    return d.toLocaleString("en-GB", { dateStyle: "short", timeStyle: "short" });
  } catch {
    return now().toLocaleString("en-GB", { dateStyle: "short", timeStyle: "short" });
  }
};

export const fmtDate = (ts) => {
  const d = validDate(ts) || now();
  try {
    return d.toLocaleDateString("en-GB");
  } catch {
    return now().toLocaleDateString("en-GB");
  }
};

export const fmtFullDateTime = (ts) => {
  const d = validDate(ts) || now();
  try {
    return d.toLocaleString("en-GB");
  } catch {
    return now().toLocaleString("en-GB");
  }
};

export const fmtISODate = (ts) => {
  const d = validDate(ts) || now();
  try {
    return d.toISOString().slice(0, 10);
  } catch {
    return now().toISOString().slice(0, 10);
  }
};

export const getNowFormatted = (format = "datetime") => {
  const n = now();
  switch (format) {
    case "time":
      return fmtTime(n);
    case "date":
      return fmtDate(n);
    case "iso":
      return fmtISODate(n);
    default:
      return fmtDateTime(n);
  }
};
