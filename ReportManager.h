#pragma once
#ifndef REPORT_MANAGER_H
#define REPORT_MANAGER_H

#include "VulnerableSourceAnalysis.h"
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/ErrorOr.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>
#include <cassert>
#include <fstream>
#include <map>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

using json = nlohmann::json;
using namespace std;

namespace hwp {

class ReportManager {
public:
  struct Params {
    std::string path_id;
    std::string produce_line;

    // sink_info
    std::string sink_info_type;
    // 其他类型 paramters 可置空
    std::string sink_info_paramters_obj_name;    // object类型
    std::string sink_info_paramters_end_line;    // line类型
    std::string sink_info_paramters_array_name;  // index类型
    std::string sink_info_paramters_array_index; // index类型
    // 用这个替换上两个，因为无法提供
    unsigned int sink_info_paramters_col;

    std::string sink_info_line_id;
    // 修改了 source_line 的类型 string -> usigned int
    unsigned int sink_info_sink_line;

    std::string source_info_type;
    std::string source_info_line_id;
    // 修改了 sink_line 的类型 string -> usigned int
    unsigned int source_info_source_line;

    //
    std::string vulnerability_type;
  };

private:
  // std::map<unsigned, unsigned> nesting_structure;
  // std::vector<std::pair<unsigned, unsigned>> matching_braces;
  std::map<string, std::map<unsigned, unsigned>> nesting_structure_array;
  std::map<string, std::vector<std::pair<unsigned, unsigned>>> matching_braces_array;

  /*
  void findStructDefinitions(const llvm::Module &M) {
      for (const llvm::DICompileUnit *CU : M.debug_compile_units()) {
          for (const llvm::DINode *Element : CU->getRetainedTypes()) {
              if (const auto *StructType = llvm::dyn_cast<llvm::DICompositeType>(Element)) {
                  if (StructType->getTag() == llvm::dwarf::DW_TAG_structure_type) {
                      llvm::StringRef StructName = StructType->getName();
                      llvm::DISubrange *LineRange = StructType->getElements()[0]->getSubrange();

                      // 输出结构体名称和定义所在的文件以及行号
                      std::cout <<endl<< "fuckingStruct " << StructName.str()
                                << " defined in: " << StructType->getFile()->getFilename().str()
                                << ":" << StructType->getLine() << std::endl;
                  }
              }
          }
      }
  }
  */

  set<std::string> getGlobalVariables(const llvm::Module &M, std::istream &file);

  // 根据 sink点 行号列号 得到 array_name array_index
  std::pair<std::string, std::string> getIndex(std::ifstream &file, unsigned int lineNum, unsigned int colNum);

  // 函数：检查指定的字符串是否出现在指定的行号范围内
  bool checkStringInRange(std::ifstream &file, const std::string &targetString, unsigned int startLine,
                          unsigned int endLine);

  // 通过dg所切出来的IR 文件得到代码行号
  std::set<unsigned> get_funlines_from_module(const llvm::Module &M);

  std::string getFunction_content_brief(std::ifstream &ifs, const llvm::Module &M, unsigned int startLine,
                                        unsigned int endLine, std::string sourceFile);

  // 从源文件中提取宏定义
  json getMacroDef(const json &array, std::ifstream &file);

  // 函数：查找指定行号范围内的宏使用
  json findMacrosInRange(std::ifstream &file, unsigned int startLine, unsigned int endLine);

  int checkStructLine(std::ifstream &file, const std::string &targetString);

  // 检查传入结构体名称是否存在于源文件中 并返回结构体定义所在的行号
  int checkStruct(std::ifstream &file, string struct_name);

  std::string resolveFilePath(const llvm::Metadata *FileMD);

  // 从 IR 文件调试信息中查找函数文件位置
  std::string findFunctionFilePath(const llvm::Module &M, const std::string &functionName);

  // 检查传入函数名称是否存在于源代码中
  bool CheckFunction(const llvm::Module &M, const llvm::Function &F);

  // 得到源代码嵌套结构，用以确定函数对应的结束行
  void get_nesting_structure(const std::string &source);

  // unsigned get_function_end_line(unsigned start_line);
  unsigned get_function_end_line(std::string file_path,unsigned start_line);

  // std::pair<unsigned, unsigned> getLineNumbers(const llvm::Function &F, const llvm::Module &M);
  std::pair<unsigned, unsigned> getLineNumbers(std::string file_path,const llvm::Function &F, const llvm::Module &M);

  std::string get_source_lines(std::ifstream &file, unsigned startLine, unsigned endLine);

  // 从IR 文件调试信息中提取结构体名称 检查是否存在于源代码中 提取结构体内容至数组
  // nlohmann::json extractStructNames(std::ifstream &file, const llvm::Module &M, unsigned int startLine,
  //                                   unsigned int endLine);
  nlohmann::json extractStructNames(std::string file_path,std::ifstream &file, const llvm::Module &M, unsigned int startLine,
                                  unsigned int endLine);

  // Json 数组去重函数
  void removeDuplicates(json &array);


  // 填充 Json文件
  json completeJson(const llvm::Module &M, Params &jInfo);

  // 接口函数
public:
  json getJson(const llvm::Module &M, const Trace &report, bool no_trace, struct Params jInfo);
};

} // namespace hwp

#endif
