#include "ReportManager.h"
#include "VulnerableSourceAnalysis.h"
#include <llvm/Support/Debug.h>
#include <iostream>
#include <istream>
#include <ranges>
#include <regex>
#include <string>

namespace hwp {

set<string> ReportManager::getGlobalVariables(const llvm::Module &M, std::istream &file) {
  set<int> lines;
  for (const llvm::GlobalVariable &G :
       M.globals() | std::views::filter([](const llvm::GlobalVariable &G) { return G.getSection() != ".modinfo"; })) {
    llvm::SmallVector<llvm::MDNode *, 1> MDs;
    G.getMetadata(llvm::LLVMContext::MD_dbg, MDs);
    // llvm::dbgs() << G << "\n";
    // llvm::dbgs() << "MDs size: " << MDs.size() << "\n";
    if (!MDs.empty()) {
      for (llvm::MDNode *md : MDs) {
        // llvm::dbgs() << "MDNode: " << *md << "\n";
        if (auto *digve = dyn_cast<llvm::DIGlobalVariableExpression>(md)) {
          // llvm::dbgs() << "digve: " << *digve << "\n";
          if (auto *dbg = digve->getVariable()) {
            lines.insert(dbg->getLine());
          }
        } else if (auto *dbg = dyn_cast<llvm::DIGlobalVariable>(md)) {
          lines.insert(dbg->getLine());
        }
      }
    }
  }
  // llvm::dbgs() << "lines: ";
  // for (auto i : lines) {
  //   llvm::dbgs() << i << ", ";
  // }
  // llvm::dbgs() << "\n";
  auto ret = lines | std::views::transform([&file](int i) {
               /// read specific line from file
               file.clear();
               file.seekg(0);
               std::string line;
               int currentLine = 1;
               while (std::getline(file, line)) {
                 if (currentLine == i) {
                   return line;
                 }
                 currentLine++;
               }
               return std::string();
             });
  return {ret.begin(), ret.end()};
}

// 根据 sink点 行号列号 得到 array_name array_index
std::pair<std::string, std::string> ReportManager::getIndex(std::ifstream &file, unsigned int lineNum,
                                                            unsigned int colNum) {
  std::string firstString, secondString;
  std::string line;
  unsigned int currentLine = 1;

  file.clear();
  file.seekg(0);

  while (std::getline(file, line)) {
    if (currentLine == lineNum) {
      // 从指定的列号开始遍历
      size_t pos = colNum - 1; // 列号从 1 开始，所以需要减 1

      while (pos < line.size() && line[pos] != '[') {
        firstString += line[pos];
        pos++;
      }

      // 跳过 '['
      if (pos < line.size() && line[pos] == '[') {
        pos++;
      }

      // 第二个 string 为 '[' 和 ']' 之间的内容
      while (pos < line.size() && line[pos] != ']') {
        secondString += line[pos];
        pos++;
      }

      break;
    }
    currentLine++;
  }

  return {firstString, secondString};
}

bool ReportManager::checkStringInRange(std::ifstream &file, const std::string &targetString, unsigned int startLine,
                                       unsigned int endLine) {
  std::string line;
  unsigned int currentLine = 1;
  bool found = false;
  file.clear(); // 清除 eof 标志
  file.seekg(0);

  while (std::getline(file, line)) {
    if (currentLine >= startLine && currentLine <= endLine) {
      if (line.find(targetString) != std::string::npos) {
        found = true;
        break;
      }
    }

    if (currentLine > endLine) {
      break;
    }
    currentLine++;
  }

  // file.close();
  return found;
}

std::set<unsigned> ReportManager::get_funlines_from_module(const llvm::Module &M) {
  std::set<unsigned> lines;

  // iterate over all instructions
  for (const auto &F : M) {
    for (const auto &B : F) {
      for (const auto &I : B) {
        const auto &Loc = I.getDebugLoc();
        // Make sure that the llvm istruction has corresponding dbg LOC
        if (Loc) {
          lines.insert(Loc.getLine());
        }
      }
    }
  }

  return lines;
}

std::string ReportManager::getFunction_content_brief(std::ifstream &ifs, const llvm::Module &M, unsigned int startLine,
                                                     unsigned int endLine, std::string sourceFile) {
  unsigned int cur_line = 1;
  std::string brief;
  std::string line; // char[1024] -> string line
  std::string file_path = sourceFile;
  std::set<unsigned> lines = get_funlines_from_module(M);
  get_nesting_structure(file_path);
  std::map<unsigned, unsigned> nesting_structure = nesting_structure_array[file_path];
  std::vector<std::pair<unsigned, unsigned>> matching_braces = matching_braces_array[file_path];
  /* fill in the lines with braces */
  /* really not efficient, but easy */
  size_t old_size;
  do {
    old_size = lines.size();
    std::set<unsigned> new_lines;

    for (unsigned i : lines) {
      // llvm::dbgs() << "newline: " << i << "\n";
      new_lines.insert(i);
      auto it = nesting_structure.find(i);
      if (it != nesting_structure.end()) {
        auto &pr = matching_braces[it->second];
        new_lines.insert(pr.first);
        new_lines.insert(pr.second);
      }
    }

    lines.swap(new_lines);
  } while (lines.size() > old_size);

  ifs.clear(); // 清除 eof 标志
  ifs.seekg(0);

  while (std::getline(ifs, line)) {
    if (lines.contains(cur_line) && cur_line >= startLine && cur_line <= endLine) {
      // brief += to_string(cur_line) + ": ";
      brief += line;
      brief += "\n";
    }

    if (ifs.bad()) {
      llvm::errs() << "An error occurred\n";
      break;
    }

    ++cur_line;
  }

  return brief;
}

// 从源文件中提取宏定义
json ReportManager::getMacroDef(const json &array, std::ifstream &file) {
  std::string line;
  json definitions = json::array();

  for (const auto &item : array) {
    file.clear();
    file.seekg(0);
    int lineNumber = 0;

    while (std::getline(file, line)) {
      ++lineNumber;

      std::string targetString = item.get<std::string>();

      if (line.find(targetString) != std::string::npos) {
        std::string str = get_source_lines(file, lineNumber, lineNumber);

        // 消除str 尾部的\r\n
        size_t endPos = str.find_last_not_of("\r\n");
        if (endPos != std::string::npos) {
          str.erase(endPos + 1);
        }

        definitions.push_back(str);
        break;
      }
    }
  }

  return definitions;
}

json ReportManager::findMacrosInRange(std::ifstream &file, unsigned int startLine, unsigned int endLine) {
  static int temp = 1;
  static std::set<std::string> macros;
  if (temp) {
    std::string line;
    std::regex macroDefineRegex(R"(^\s*#\s*define\s+([a-zA-Z_][a-zA-Z0-9_]*)\b)");

    file.clear(); // 清除 eof 标志
    file.seekg(0);
    while (std::getline(file, line)) {
      std::smatch match;
      if (std::regex_search(line, match, macroDefineRegex)) {
        if (match.size() > 1) {
          macros.insert(match[1].str()); // 插入宏名称
        }
      }
      temp = 0;
    }
  }

  json macroArray = json::array();
  std::string line;
  unsigned int currentLine = 1;
  // std::ifstream file1(filePath);

  file.clear();
  file.seekg(0);

  // 遍历文件查找范围内的宏使用
  while (std::getline(file, line)) {
    if (currentLine >= startLine && currentLine <= endLine) {
      for (const auto &macro : macros) {
        if (line.find(macro) != std::string::npos) {
          macroArray.push_back(macro);
        }
      }
    }
    if (currentLine > endLine) {
      break;
    }
    currentLine++;
  }

  // file1.close();
  return macroArray;
}

int ReportManager::checkStructLine(std::ifstream &file, const std::string &targetString) {
  std::string line;
  int lineNumber = 0;

  file.clear();
  file.seekg(0);
  while (std::getline(file, line)) {
    lineNumber++;
    if (line.find(targetString) != std::string::npos) {
      return lineNumber; // 返回匹配的行号
    }
  }

  // file.close();
  return -1;
}

// 检查传入结构体名称是否存在于源文件中 并返回结构体定义所在的行号
int ReportManager::checkStruct(std::ifstream &file, string struct_name) {
  // cout<<endl<<"checkStruct"<<endl;
  static int temp = 1;
  static std::map<std::string, int> structMap;

  if (temp) {
    file.clear();
    file.seekg(0);
    std::string line;
    int lineNumber = 0;
    std::regex structRegex(R"(struct\s+([a-zA-Z_]\w*)\s*\{)");   // struct test{类型
    std::regex structRegex2(R"(struct\s+(\w+)\s+\w+\s*=\s*\{)"); // static struct file_operations fops = {类型

    // static struct file_operations fops = {类型  struct test{类型
    while (std::getline(file, line)) {
      lineNumber++;
      std::smatch match;
      if (std::regex_search(line, match, structRegex)) {
        structMap[match[1]] = lineNumber;
      } else if (std::regex_search(line, match, structRegex2)) {
        structMap[match[1]] = lineNumber;
      }
    }

    file.clear();
    file.seekg(0);

    lineNumber = 0;
    bool structFound = false;
    std::string structName;
    int temp1 = 0;

    // typedef struct 类型
    while (std::getline(file, line)) {
      lineNumber++;
      if (line.find("typedef struct") != std::string::npos) {
        structFound = true;
        temp1 = lineNumber;
      }
      if (structFound) {
        size_t pos = line.find('}');
        if (pos != std::string::npos) {
          std::istringstream iss(line.substr(pos + 1));
          iss >> structName;
          if (!structName.empty()) {
            size_t endPos = structName.find_last_not_of(";");
            if (endPos != std::string::npos) {
              structName.erase(endPos + 1);
            }
            structMap[structName] = temp1;
            structFound = false;
          }
        }
      }
    }

    temp = 0;

    // for (const auto& entry : structMap) {
    //     std::cout <<endl<< "Key: " << entry.first << ", Value: " << entry.second << std::endl;
    // }
  }

  if (structMap.find(struct_name) != structMap.end()) {
    return structMap[struct_name];
  }

  return 0;
}

std::string ReportManager::resolveFilePath(const llvm::Metadata *FileMD) {
  if (const llvm::DIFile *File = llvm::dyn_cast<llvm::DIFile>(FileMD)) {
    auto filename = File->getFilename();
    auto filedir = File->getDirectory();
    if (!filename.empty() && filename[0] == '/') {
      return filename.str();
    }
    return (filedir + "/" + filename).str();
  }
  std::cerr << "警告: 无法解析文件元数据。\n";
  return "Unknown";
}
std::string ReportManager::findFunctionFilePath(const llvm::Module &M, const std::string &functionName) {
  llvm::DebugInfoFinder Finder;
  Finder.processModule(M);

  for (const auto &SP : Finder.subprograms()) {
    if (SP->getName() == functionName) {
      const llvm::MDNode *FileNode = SP->getFile();
      return resolveFilePath(FileNode);
    }
  }

  // std::cerr << "函数 " << functionName << " 在 IR 文件中未找到。\n";
  return "Unknown";
}

bool ReportManager::CheckFunction(const llvm::Module &M, const llvm::Function &F) {
  string filePath;

  filePath = findFunctionFilePath(M, F.getName().str());

  if (filePath != "Unknown") {
    if (filePath.find("/include/") == std::string::npos) {
      return true;
    }
  }

  return false;

  // static std::map<std::string, int> functionMap;
  // static int temp = 1;

  // if (temp) {
  //   std::string sourceCode((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  //   // file.close();

  //   // std::regex regex(R"(\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\()");
  //   std::regex regex(R"(\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*\{)");

  //   std::sregex_iterator iter(sourceCode.begin(), sourceCode.end(), regex);
  //   std::sregex_iterator end;

  //   while (iter != end) {
  //     std::smatch match = *iter;
  //     std::string functionName = match.str(1);
  //     // cout<<endl<<"functionName="<<match.str(1)<<endl;

  //     functionMap[functionName] = 0;

  //     ++iter;
  //   }
  //   temp = 0;
  // }

  // if (functionMap.contains(functionName)) {
  //   return true;
  // }
  // return false;
}

void ReportManager::get_nesting_structure(const std::string &source) { // 获得嵌套结构
  std::ifstream ifs(source);
  if (!ifs.is_open() || ifs.bad()) {
    std::cerr << "Failed opening given source file: " << source << "\n";
    abort();
  }

  if(nesting_structure_array.find(source)!=nesting_structure_array.end()){
    return;
  }

  char ch;
  unsigned cur_line = 1;
  unsigned idx;
  std::stack<unsigned> nesting;
  std::map<unsigned, unsigned> nesting_structure;
  std::vector<std::pair<unsigned, unsigned>> matching_braces;

  while (ifs.get(ch)) {
    // Debug output for current character and line
    // std::cerr << "Character: " << ch << ", Line: " << cur_line << "\n";
    // std::cerr << "Stack top: " << (nesting.empty() ? "empty" : std::to_string(nesting.top())) << "\n";

    switch (ch) {
    case '\n':
      ++cur_line;
      if (!nesting.empty()) {
        nesting_structure.emplace(cur_line - 1, nesting.top());
        // std::cerr << "Updated nesting_structure at line " << cur_line-1 << " with start index " << nesting.top() <<
        // "\n";
      }
      break;
    case '{':
      nesting.push(matching_braces.size());
      matching_braces.emplace_back(cur_line, 0);
      break;
    case '}':
      if (nesting.empty()) {
        std::cerr << "Mismatched closing brace at line " << cur_line << "\n";
        abort();
      }
      idx = nesting.top();
      assert(idx < matching_braces.size());
      assert(matching_braces[idx].second == 0);
      matching_braces[idx].second = cur_line;
      nesting.pop();
      break;
    default:
      break;
    }
  }

  nesting_structure_array[source]=nesting_structure;
  matching_braces_array[source]=matching_braces;

  if (ifs.bad()) {
    std::cerr << "Error occurred while reading the file.\n";
    abort();
  }

  ifs.close();

  // Debug output for nesting_structure
  // std::cerr << "Nesting structure:\n";
  // for (const auto &pair : nesting_structure) {
  //   std::cerr << "Line " << pair.first << " starts at " << pair.second << "\n";
  // }
  // std::cerr << "Matching braces:\n";
  // for (const auto &pair : matching_braces) {
  //   std::cerr << "Start line " << pair.first << ", End line " << pair.second << "\n";
  // }
}
unsigned ReportManager::get_function_end_line(std::string file_path,unsigned start_line) {

  std::map<unsigned, unsigned> nesting_structure = nesting_structure_array[file_path];
  std::vector<std::pair<unsigned, unsigned>> matching_braces = matching_braces_array[file_path];

  unsigned end_line = 0;
  auto it = nesting_structure.find(start_line);

  int temp = 0;
  while (it == nesting_structure.end()) {
    temp++;
    start_line++;
    it = nesting_structure.find(start_line);
    if (temp > 50) {
      break;
    }
  }

  if (it != nesting_structure.end()) {
    unsigned start_idx = it->second;
    if (start_idx < matching_braces.size()) {
      end_line = matching_braces[start_idx].second;
      if (end_line == 0) {
        std::cerr << "End line not found for start line " << start_line << "\n";
        return 0;
      }
    } else {
      std::cerr << "Invalid start index " << start_idx << "\n";
      return 0;
    }
  } else {
    std::cerr << "Start line " << start_line << " not found in nesting structure.\n";
    return 0;
  }
  return end_line;
}

std::pair<unsigned, unsigned> ReportManager::getLineNumbers(std::string file_path,const llvm::Function &F, const llvm::Module &M) {
  unsigned startLine = 0;
  unsigned endLine = 0;

  llvm::DebugInfoFinder Finder;
  Finder.processModule(M);

  for (const auto &FMD : Finder.subprograms()) {
    // std::cerr << "Found subprogram: " << FMD->getName().str() << ", Line: " << FMD->getLine() << "\n";
    if (FMD->getName() == F.getName()) {
      startLine = FMD->getLine();
      endLine = get_function_end_line(file_path,startLine);
      break;
    }
  }

  if (startLine == 0) {
    std::cerr << "Failed to find start line for function " << F.getName().str() << "\n";
  }
  if (endLine == 0) {
    std::cerr << "Failed to find end line for function " << F.getName().str() << "\n";
  }

  return {startLine, endLine};
}

// 根据行号返回源文件内容
std::string ReportManager::get_source_lines(std::ifstream &file, unsigned startLine, unsigned endLine) {
  file.clear(); // 清除 eof 标志
  file.seekg(0);

  std::string result;
  std::string line;
  unsigned currentLine = 1;
  while (std::getline(file, line)) {
    if (currentLine >= startLine && currentLine <= endLine) {
      result += line + "\n";
    }
    if (currentLine > endLine) {
      break;
    }
    ++currentLine;
  }

  return result;
}

nlohmann::json ReportManager::extractStructNames(std::string file_path,std::ifstream &file, const llvm::Module &M, unsigned int startLine,
                                                 unsigned int endLine) {
  file.clear(); // 清除 eof 标志
  file.seekg(0);

  json struct_names = json::array();
  for (const llvm::StructType *ST : M.getIdentifiedStructTypes()) {
    if (ST->hasName()) {
      std::string structName = ST->getName().str();
      std::string prefix = "struct.";

      if (structName.starts_with(prefix)) {
        structName = structName.substr(prefix.length());
      }
      if (checkStruct(file, structName) && checkStringInRange(file, structName, startLine, endLine)) {
        unsigned int startLine1 = checkStruct(file, structName);
        unsigned int endLine1 = get_function_end_line(file_path,startLine1);
        struct_names.push_back(get_source_lines(file, startLine1, endLine1));
      }

      // std::cout << "Found struct: " << structName << "\n";
    }
  }
  return struct_names;
}

void ReportManager::removeDuplicates(json &array) {
  std::set<json> uniqueElements;
  json result = json::array();

  for (const auto &element : array) {
    if (uniqueElements.insert(element).second) {
      result.push_back(element);
    }
  }

  array = result;
}

;

json ReportManager::completeJson(const llvm::Module &M, Params &jInfo) {
  json j;

  json function_names = json::array();
  // json function_file_paths = json::array();
  std::set<std::string> function_file_paths;
  json function_content = json::array();
  json function_content_brief = json::array();
  json macros = json::array();
  json structs = json::array();

  for (const auto &F : M) {

    if (CheckFunction(M, F)) {
      string function_name = F.getName().str();
      string file_path = findFunctionFilePath(M, function_name);
      get_nesting_structure(file_path);
      auto [startLine, endLine] = getLineNumbers(file_path,F, M);

      std::ifstream file(file_path);
      if (!file.is_open()) {
        std::cerr << "Failed to open file: " << file_path << std::endl;
        json j;
        j["failed"] = "Failed to open file";
        return j;
      }


      function_names.push_back(function_name);

      function_file_paths.insert(findFunctionFilePath(M, function_name));

      if (startLine > 0 && endLine > 0) {
        std::string sourceCode = get_source_lines(file, startLine, endLine);
        function_content.push_back(sourceCode);
      }

      // llvm::dbgs() << "[startLine, endLine]: " << startLine << ", " << endLine << "\n";
      function_content_brief.push_back(getFunction_content_brief(file, M, startLine, endLine, file_path));

      json temp = json::array();
      temp = findMacrosInRange(file, startLine, endLine);
      macros.insert(macros.end(), temp.begin(), temp.end());

      //ToDo：多个文件链接在一起的情况结构体的提取是否可以正常工作？
      temp = extractStructNames(file_path,file, M, startLine, endLine);
      structs.insert(structs.end(), temp.begin(), temp.end());
    }
  }

  removeDuplicates(macros);
  removeDuplicates(structs);
  // macros = getMacroDef(macros, file);

  j["function_name"] = function_names;
  j["relative_path"] = function_file_paths;
  j["function_content"] = function_content;
  j["function_content_brief"] = function_content_brief;
  j["struct"] = structs;
  j["macro"] = macros;
  j["language"] = "c";
  j["vulnerability_type"] = jInfo.vulnerability_type;
  j["path_id"] = jInfo.path_id;
  j["produce_line"] = jInfo.produce_line;
  j["sink_info"]["type"] = jInfo.sink_info_type;

  if (jInfo.sink_info_type == "object") {
    j["sink_info"]["paramters"]["obj_name"] = jInfo.sink_info_paramters_obj_name;
  } else if (jInfo.sink_info_type == "line") {
    j["sink_info"]["paramters"]["end_line"] = jInfo.sink_info_paramters_end_line;
  } else if (jInfo.sink_info_type == "index") {
    // auto [name, index] = getIndex(file, jInfo.sink_info_sink_line, jInfo.sink_info_paramters_col);
    // j["sink_info"]["paramters"]["array_name"] = name;
    // j["sink_info"]["paramters"]["array_index"] = index;
  }
  j["sink_info"]["line_id"] = jInfo.sink_info_line_id;
  // j["sink_info"]["sink_line"] = get_source_lines(file, jInfo.sink_info_sink_line, jInfo.sink_info_sink_line);

  j["source_info"]["line_id"] = jInfo.source_info_line_id;
  // j["source_info"]["source_line"] =
  //         get_source_lines(file, jInfo.source_info_source_line, jInfo.source_info_source_line);

  // j["global_variable"] = getGlobalVariables(M, file);


  // findStructDefinitions(M);

  return j;
}

json ReportManager::getJson(const llvm::Module &M, const Trace &report, bool no_trace, struct Params jInfo) {
  // std::string filePath;
  // int temp = 1;

  // for (const auto &F : M) {
  //   filePath = findFunctionFilePath(M, F.getName().str());

  //   if (filePath != "Unknown") {
  //     if (filePath.find("/include/") == std::string::npos) {
  //       temp = 0;
  //       break;
  //     }
  //   }
  // }
  // if (temp) {
  //   std::cerr << "Failed to find file ";
  //   json j;
  //   j["failed"] = "Failed to find file";
  //   return j;
  // }

  // std::ifstream file(filePath);
  // if (!file.is_open()) {
  //   std::cerr << "Failed to open file: " << filePath << std::endl;
  //   json j;
  //   j["failed"] = "Failed to open file";
  //   return j;
  // }

  // get_nesting_structure(filePath);
  auto ret = completeJson(M,jInfo);

  if (!no_trace) {
    ret["trace"] = nlohmann::json::array();
    for (const auto &v : report.trace) {
      std::string str;
      llvm::raw_string_ostream(str) << *v;
      ret["trace"].push_back(str);
    }
  }
  ret["source_info"]["source_type"] = jInfo.source_info_type;
  return ret;
}

/*
int main(int argc, char **argv) {
  if (argc != 4) {
    cerr << "用法: " << argv[0] << " <input.ll> <source_code.c> <output.json>" << endl;
    return 1;
  }

  llvm::LLVMContext Context;
  llvm::SMDiagnostic Err;
  auto ModuleOrErr = llvm::parseIRFile(argv[1], Err, Context);
  if (!ModuleOrErr) {
    Err.print(argv[0], llvm::errs());
    return 1;
  }
  auto *M = std::move(ModuleOrErr.get());

  // std::string sourceCodePath = argv[2];
  // std::string llFilePath = argv[1];

  // std::ifstream file(sourceCodePath);
  // if (!file.is_open()) {
  //     std::cerr << "Failed to open file: " << sourceCodePath << std::endl;
  // }

  // get_nesting_structure(sourceCodePath);
  // jsonInfo jInfo;

  // json j = completeJson(*M,file,jInfo);
  struct jsonInfo jInfo;

  json j = getJson(*M, jInfo);

  std::ofstream outputFile(argv[3]);
  if (!outputFile.is_open()) {
    cerr << "打开输出文件失败: " << argv[3] << endl;
    return 1;
  }

  outputFile << j.dump(4); // 使用缩进的格式输出
  outputFile.close();

  cout << "成功将函数信息输出到文件: " << argv[3] << endl;

  return 0;
}
*/

} // namespace hwp
