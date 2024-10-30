import type { ChatCompletionInputMessage, GenerationParameters } from "../tasks";
export interface StringifyMessagesOptions {
    sep: string;
    start: string;
    end: string;
    attributeKeyQuotes?: boolean;
    customContentEscaper?: (str: string) => string;
}
export declare function stringifyMessages(messages: ChatCompletionInputMessage[], opts: StringifyMessagesOptions): string;
type PartialGenerationParameters = Partial<Pick<GenerationParameters, "temperature" | "max_tokens" | "top_p">>;
export interface StringifyGenerationConfigOptions {
    sep: string;
    start: string;
    end: string;
    attributeValueConnector: string;
    attributeKeyQuotes?: boolean;
}
export declare function stringifyGenerationConfig(config: PartialGenerationParameters, opts: StringifyGenerationConfigOptions): string;
export {};
//# sourceMappingURL=common.d.ts.map