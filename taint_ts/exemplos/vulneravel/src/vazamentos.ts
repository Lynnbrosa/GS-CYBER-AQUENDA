import { listarLembretes, obterConsulta } from "./banco";
import { enviar, resumoDoDia, rotulo } from "./util";
import { Linking } from "react-native";
import * as Crypto from "expo-crypto";
import AsyncStorage from "@react-native-async-storage/async-storage";

// V1: lembretes vão direto para um servidor de "analytics"
export async function v1() {
  const lembretes = await listarLembretes();
  await fetch("https://analytics.exemplo.com/evento", { method: "POST", body: JSON.stringify(lembretes) });
}

// V2: passa por utilitário em outro arquivo e por .map
export async function v2() {
  const texto = resumoDoDia(await listarLembretes());
  await enviar("https://api.exemplo.com/diario", { texto });
}

// V3: consulta vai num link do WhatsApp ("compartilhar")
export async function v3() {
  const c = await obterConsulta(7);
  await Linking.openURL(`https://wa.me/?text=${encodeURIComponent(`Minha consulta: ${c.titulo} em ${c.local}`)}`);
}

// V4: log de depuração esquecido
export async function v4() {
  const [primeiro] = await listarLembretes();
  console.log("lembrete", primeiro.anotacao);
}

// V5: guarda sem cifra
export async function v5() {
  const lista = await listarLembretes();
  await AsyncStorage.setItem("cache", JSON.stringify(lista));
}

// V6: PIN no log
export function definirPin(pin: string) {
  console.warn("pin criado", pin);
}

// OK1: só o hash sai (não pode ser apontado)
export async function ok1(pin: string) {
  const h = await Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, pin);
  await fetch("https://api.exemplo.com/h", { method: "POST", body: h });
}

// OK2: utilitário compartilhado, chamado aqui com texto público (não pode herdar o dado de v2)
export async function ok2() {
  await enviar("https://api.exemplo.com/publico", { texto: rotulo("bom dia") });
}

// OK3: só o id local (campo neutro) e a contagem saem
export async function ok3() {
  const lembretes = await listarLembretes();
  await fetch(`https://api.exemplo.com/sync?id=${lembretes[0].id}&n=${lembretes.length}`);
}
