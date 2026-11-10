declare module "capstone-wasm" {
  export interface CsInsn {
    id: number;
    address: number | bigint;
    size: number;
    bytes: Uint8Array;
    mnemonic: string;
    opStr: string;
  }
  export interface CsOptions { address?: number | bigint; count?: number }
  export class Capstone {
    constructor(arch: number, mode: number);
    disasm(data: number[] | Uint8Array, options?: CsOptions): CsInsn[];
    close(): void;
  }
  export const Const: Record<string, number>;
  export function loadCapstone(): Promise<void>;
}
