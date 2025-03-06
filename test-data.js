// Test loading the data.js file
try {
  const fs = require('fs');
  const fileContents = fs.readFileSync('./js/data.js', 'utf8');
  console.log("Successfully read data.js file");
  
  // Try to parse/evaluate the JS
  try {
    // Use the Function constructor to create a function that evaluates the code
    const evalFn = new Function(fileContents + '; return vulnerabilitiesData;');
    const data = evalFn();
    console.log(`Successfully parsed data.js, found ${data.length} vulnerabilities`);
  } catch (evalErr) {
    console.error("Error parsing data.js content:", evalErr);
    // Print line number information if available
    if (evalErr.stack) {
      console.error("Stack trace:", evalErr.stack);
    }
    
    // Try to locate the syntax error
    const lines = fileContents.split('\n');
    for (let i = 0; i < lines.length; i++) {
      try {
        new Function(lines.slice(0, i+1).join('\n'));
      } catch (e) {
        console.error(`Syntax error might be at line ${i+1}:`, lines[i]);
        break;
      }
    }
  }
} catch (err) {
  console.error("Error reading data.js file:", err);
}