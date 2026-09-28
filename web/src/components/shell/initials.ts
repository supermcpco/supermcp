/**
 * One or two letters that stand for a person in a round badge: the first
 * and last word of their name, or else the parts of their address before
 * the @ (split on dots, dashes, underscores and pluses). Parts that do not
 * start with a letter are skipped, so "browser-1759@…" is "B", not "B1".
 */
export function initials(name: string | undefined, email: string): string {
  const words = (name?.trim() ? name.trim().split(/\s+/) : email.split("@")[0].split(/[._+-]+/)).filter((w) =>
    /^\p{L}/u.test(w),
  );
  const picked = words.length > 1 ? [words[0], words[words.length - 1]] : words.slice(0, 1);
  const letters = picked.map((w) => [...w][0].toLocaleUpperCase()).join("");
  return letters || "?";
}
