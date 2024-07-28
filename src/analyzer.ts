// src/analyzer.ts
import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

const documentsPath = path.join(os.homedir(), 'Documents', 'Securiter');
const logFilePath = path.join(documentsPath, 'analysis.log');

export async function initializeLogFile() {
    if (!fs.existsSync(documentsPath)) {
        fs.mkdirSync(documentsPath, { recursive: true });
    }
    fs.writeFileSync(logFilePath, `Extension Analysis Log\n=======================\n\n`, 'utf-8');
}

export async function logExtensionAnalysis(extension: vscode.Extension<any>, analysisResults: AnalysisResults) {
    const groupedMaliciousResults: { [key: string]: { count: number, type: string } } = {};
    analysisResults.malicious.forEach(result => {
        const key = `${result.code} (${result.type})`;
        if (groupedMaliciousResults[key]) {
            groupedMaliciousResults[key].count++;
        } else {
            groupedMaliciousResults[key] = { count: 1, type: result.type };
        }
    });

    const formattedMaliciousResults = Object.entries(groupedMaliciousResults).map(([code, info]) => {
        return `${code} (x${info.count})`;
    }).join('\n');

    const uniqueUrls = Array.from(new Set(analysisResults.urls));

    const logContent = `
Extension: ${extension.packageJSON.name}
Version: ${extension.packageJSON.version}
Publisher: ${extension.packageJSON.publisher}
Description: ${extension.packageJSON.description}
Malicious Code Detected: ${analysisResults.malicious.length > 0 ? 'Yes' : 'No'}
Details:
${formattedMaliciousResults}
URLs Found:
${uniqueUrls.join('\n')}
=======================\n`;

    fs.appendFileSync(logFilePath, logContent, 'utf-8');
}

interface AnalysisResult {
    file: string;
    line: number;
    code: string;
    type: string;
}

interface AnalysisResults {
    malicious: AnalysisResult[];
    urls: string[];
}

export async function analyzeExtension(extension: vscode.Extension<any>): Promise<AnalysisResults> {
    const extensionPath = extension.extensionPath;
    vscode.window.showInformationMessage(`Analyzing extension: ${extension.packageJSON.name}`);

    const files = await getFiles(extensionPath);
    const maliciousResults: AnalysisResult[] = [];
    const urls: string[] = [];
    for (const file of files) {
        const content = fs.readFileSync(file, 'utf-8');
        const detectedIssues = detectMaliciousCode(content);
        const foundUrls = detectUrls(content);
        if (detectedIssues.length > 0) {
            detectedIssues.forEach(issue => {
                maliciousResults.push({
                    file,
                    line: issue.line,
                    code: issue.code,
                    type: issue.type
                });
            });
        }
        urls.push(...foundUrls);
    }
    return { malicious: maliciousResults, urls };
}

function getFiles(dir: string): Promise<string[]> {
    return new Promise((resolve, reject) => {
        let results: string[] = [];
        fs.readdir(dir, (err, list) => {
            if (err) return reject(err);
            let pending = list.length;
            if (!pending) return resolve(results);
            list.forEach(file => {
                file = path.resolve(dir, file);
                fs.stat(file, (err, stat) => {
                    if (stat && stat.isDirectory()) {
                        getFiles(file).then(res => {
                            results = results.concat(res);
                            if (!--pending) resolve(results);
                        });
                    } else {
                        results.push(file);
                        if (!--pending) resolve(results);
                    }
                });
            });
        });
    });
}

function detectMaliciousCode(content: string): AnalysisResult[] {
    const execPattern = /exec\((.*?)\)/;
    const potentiallyDangerousCommands = [
        'cmd', 'powershell', 'bash', 'sh', 'curl', 'wget', 'rm', 'del', 'mv', 'scp', 'ftp', 'tftp', 'ssh', 'netcat', 'nc', 'telnet', 'ping', 'kill', 'pkill', 'killall', 'reboot', 'shutdown', 'halt', 'init', 'systemctl', 'service', 'chown', 'chmod', 'chgrp', 'useradd', 'usermod', 'userdel', 'groupadd', 'groupmod', 'groupdel', 'passwd', 'su', 'sudo', 'visudo', 'adduser', 'userdel', 'usermod', 'groupadd', 'groupdel', 'groupmod', 'passwd', 'chown', 'chmod', 'chgrp', 'useradd', 'usermod', 'userdel', 'groupadd', 'groupmod', 'groupdel', 'passwd', 'su', 'sudo', 'visudo', 'adduser', 'userdel', 'usermod', 'groupadd', 'groupdel', 'groupmod', 'passwd', 'chown', 'chmod', 'chgrp', 'useradd', 'usermod', 'userdel', 'groupadd', 'groupmod', 'groupdel', 'passwd', 'su', 'sudo', 'visudo', 'adduser', 'userdel', 'usermod', 'groupadd', 'groupdel', 'groupmod', 'passwd', 'chown', 'chmod', 'chgrp', 'useradd', 'usermod', 'userdel', 'groupadd', 'groupmod', 'groupdel', 'passwd', 'su', 'sudo', 'visudo', 'adduser', 'userdel', 'usermod', 'groupadd', 'groupdel', 'groupmod', 'passwd', 'chown', 'chmod', 'chgrp', 'useradd', 'usermod', 'userdel', 'groupadd', 'groupmod', 'groupdel', 'passwd', 'su', 'sudo', 'visudo', 'adduser', 'userdel', 'usermod', 'groupadd', 'groupdel', 'groupmod', 'passwd', 'chown', 'chmod', 'chgrp', 'useradd', 'usermod', 'userdel', 'groupadd', 'groupmod', 'groupdel', 'passwd', 'su', 'sudo', 'visudo', 'adduser', 'userdel', 'usermod', 'groupadd', 'groupdel', 'groupmod', 'passwd', 'chown', 'chmod', 'chgrp'
    ];

    const detected: AnalysisResult[] = [];
    const lines = content.split('\n');
    lines.forEach((line, index) => {
        const execMatch = line.match(execPattern);
        if (execMatch) {
            const command = execMatch[1];
            if (potentiallyDangerousCommands.some(cmd => command.includes(cmd))) {
                detected.push({
                    file: '', // The file name will be added later in the analyzeExtension function
                    line: index + 1,
                    code: command,
                    type: 'potentially dangerous exec usage'
                });
            }
        }
    });
    return detected;
}

function detectUrls(content: string): string[] {
    const urlPattern = /https?:\/\/[\w/:%#\$&\?\(\)~\.=\+\-]+/g;
    const urls: string[] = [];
    let match;
    while ((match = urlPattern.exec(content)) !== null) {
        urls.push(match[0]);
    }
    return urls;
}
