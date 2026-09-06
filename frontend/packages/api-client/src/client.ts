import createClient from "openapi-fetch";

import type { paths as ProductPaths } from "./generated/product";

export function createProductClient(baseUrl: string) {
  return createClient<ProductPaths>({ baseUrl });
}
