// src/extension.ts
import * as vscode from 'vscode';
import { analyzeExtension, initializeLogFile, logExtensionAnalysis } from './analyzer';

export function activate(context: vscode.ExtensionContext) {
    initializeLogFile();

    let disposable = vscode.commands.registerCommand('extension.analyzeExtensions', async () => {
        vscode.window.showInformationMessage('Analyze Extensions command executed');

        const extensions = vscode.extensions.all;
        for (const ext of extensions) {
            if (ext.packageJSON.name === 'securiter') {
                continue;
            }

            const analysisResults = await analyzeExtension(ext);
            await logExtensionAnalysis(ext, analysisResults);
            
            if (analysisResults) {
                vscode.window.showWarningMessage(`Possible malicious code found in extension: ${ext.packageJSON.name}`);
            }
        }

        vscode.window.showInformationMessage('Extensions analysis completed. Check the log file for details.');
    });

    context.subscriptions.push(disposable);
}

export function deactivate() {}
