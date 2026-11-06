// Utilitários usados em vários lugares (testam o resumo por função).
export function resumoDoDia(itens: { titulo: string }[]) {
  return itens.map((i) => i.titulo).join(", ");
}
export function enviar(url: string, corpo: unknown) {
  return fetch(url, { method: "POST", body: JSON.stringify(corpo) });
}
export function rotulo(texto: string) {
  return `[${texto}]`;
}
