#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
//#include <random>
#include <time.h>
#include "mat.h"

float** rotate180(float** mat, nSize matSize)// 矩阵翻转180度
{
	int i,c,r;
	int outSizeW=matSize.c;
	int outSizeH=matSize.r;
	float** outputData=(float**)malloc(outSizeH*sizeof(float*));
	for(i=0;i<outSizeH;i++)
		outputData[i]=(float*)malloc(outSizeW*sizeof(float));

	for(r=0;r<outSizeH;r++)
		for(c=0;c<outSizeW;c++)
			outputData[r][c]=mat[outSizeH-r-1][outSizeW-c-1];

	return outputData;
}

// 关于卷积和相关操作的输出选项
// 这里共有三种选择：full、same、valid，分别表示
// full指完全，操作后结果的大小为inSize+(mapSize-1)
// same指同输入相同大小
// valid指完全操作后的大小，一般为inSize-(mapSize-1)大小，其不需要将输入添0扩大。

float** correlation(float** map,nSize mapSize,float** inputData,nSize inSize,int type)// 互相关
{
	// 这里的互相关是在后向传播时调用，类似于将Map反转180度再卷积
	// 为了方便计算，这里先将图像扩充一圈
	// 这里的卷积要分成两拨，偶数模板同奇数模板
	int i,j,c,r;
	int halfmapsizew;
	int halfmapsizeh;
	if(mapSize.r%2==0&&mapSize.c%2==0){ // 模板大小为偶数
		halfmapsizew=(mapSize.c)/2; // 卷积模块的半瓣大小
		halfmapsizeh=(mapSize.r)/2;
	}else{
		halfmapsizew=(mapSize.c-1)/2; // 卷积模块的半瓣大小
		halfmapsizeh=(mapSize.r-1)/2;
	}

	// 这里先默认进行full模式的操作，full模式的输出大小为inSize+(mapSize-1)
	int outSizeW=inSize.c+(mapSize.c-1); // 这里的输出扩大一部分
	int outSizeH=inSize.r+(mapSize.r-1);
	float** outputData=(float**)malloc(outSizeH*sizeof(float*)); // 互相关的结果扩大了
	for(i=0;i<outSizeH;i++)
		outputData[i]=(float*)calloc(outSizeW,sizeof(float));

	// 为了方便计算，将inputData扩大一圈
	float** exInputData=matEdgeExpand(inputData,inSize,mapSize.c-1,mapSize.r-1);

	for(j=0;j<outSizeH;j++)
		for(i=0;i<outSizeW;i++)
			for(r=0;r<mapSize.r;r++)
				for(c=0;c<mapSize.c;c++){
					outputData[j][i]=outputData[j][i]+map[r][c]*exInputData[j+r][i+c];
				}

	for(i=0;i<inSize.r+2*(mapSize.r-1);i++)
		free(exInputData[i]);
	free(exInputData);

	nSize outSize={outSizeW,outSizeH};
	switch(type){ // 根据不同的情况，返回不同的结果
	case full: // 完全大小的情况
		return outputData;
	case same:{
		float** sameres=matEdgeShrink(outputData,outSize,halfmapsizew,halfmapsizeh);
		for(i=0;i<outSize.r;i++)
			free(outputData[i]);
		free(outputData);
		return sameres;
		}
	case valid:{
		float** validres;
		if(mapSize.r%2==0&&mapSize.c%2==0)
			validres=matEdgeShrink(outputData,outSize,halfmapsizew*2-1,halfmapsizeh*2-1);
		else
			validres=matEdgeShrink(outputData,outSize,halfmapsizew*2,halfmapsizeh*2);
		for(i=0;i<outSize.r;i++)
			free(outputData[i]);
		free(outputData);
		return validres;
		}
	default:
		return outputData;
	}
}

float** cov(float** map,nSize mapSize,float** inputData,nSize inSize,int type) // 卷积操作
{
	// 卷积操作可以用旋转180度的特征模板相关来求
	float** flipmap=rotate180(map,mapSize); //旋转180度的特征模板
	float** res=correlation(flipmap,mapSize,inputData,inSize,type);
	int i;
	for(i=0;i<mapSize.r;i++)
		free(flipmap[i]);
	free(flipmap);
	return res;
}

// 这个是矩阵的上采样（等值内插），upc及upr是内插倍数
float** UpSample(float** mat,nSize matSize,int upc,int upr)
{ 
	int i,j,m,n;
	int c=matSize.c;
	int r=matSize.r;
	float** res=(float**)malloc((r*upr)*sizeof(float*)); // 结果的初始化
	for(i=0;i<(r*upr);i++)
		res[i]=(float*)malloc((c*upc)*sizeof(float));

	for(j=0;j<r*upr;j=j+upr){
		for(i=0;i<c*upc;i=i+upc)// 宽的扩充
			for(m=0;m<upc;m++)
				res[j][i+m]=mat[j/upr][i/upc];

		for(n=1;n<upr;n++)      //  高的扩充
			for(i=0;i<c*upc;i++)
				res[j+n][i]=res[j][i];
	}
	return res;
}

// 给二维矩阵边缘扩大，增加addw大小的0值边
float** matEdgeExpand(float** mat,nSize matSize,int addc,int addr)
{ // 向量边缘扩大
	int i,j;
	int c=matSize.c;
	int r=matSize.r;
	float** res=(float**)malloc((r+2*addr)*sizeof(float*)); // 结果的初始化
	for(i=0;i<(r+2*addr);i++)
		res[i]=(float*)malloc((c+2*addc)*sizeof(float));

	for(j=0;j<r+2*addr;j++){
		for(i=0;i<c+2*addc;i++){
			if(j<addr||i<addc||j>=(r+addr)||i>=(c+addc))
				res[j][i]=(float)0.0;
			else
				res[j][i]=mat[j-addr][i-addc]; // 复制原向量的数据
		}
	}
	return res;
}

// 给二维矩阵边缘缩小，擦除shrinkc大小的边
float** matEdgeShrink(float** mat,nSize matSize,int shrinkc,int shrinkr)
{ // 向量的缩小，宽缩小addw，高缩小addh
	int i,j;
	int c=matSize.c;
	int r=matSize.r;
	float** res=(float**)malloc((r-2*shrinkr)*sizeof(float*)); // 结果矩阵的初始化
	for(i=0;i<(r-2*shrinkr);i++)
		res[i]=(float*)malloc((c-2*shrinkc)*sizeof(float));

	
	for(j=0;j<r;j++){
		for(i=0;i<c;i++){
			if(j>=shrinkr&&i>=shrinkc&&j<(r-shrinkr)&&i<(c-shrinkc))
				res[j-shrinkr][i-shrinkc]=mat[j][i]; // 复制原向量的数据
		}
	}
	return res;
}

void savemat(float** mat,nSize matSize,const char* filename)
{
	FILE  *fp=NULL;
	fp=fopen(filename,"wb");
	if(fp==NULL)
		printf("write file failed\n");

	int i;
	for(i=0;i<matSize.r;i++)
		fwrite(mat[i],sizeof(float),matSize.c,fp);
	fclose(fp);
}

void addmat(float** res, float** mat1, nSize matSize1, float** mat2, nSize matSize2)// 矩阵相加
{
	int i,j;
	if(matSize1.c!=matSize2.c||matSize1.r!=matSize2.r)
		printf("ERROR: Size is not same!");

	for(i=0;i<matSize1.r;i++)
		for(j=0;j<matSize1.c;j++)
			res[i][j]=mat1[i][j]+mat2[i][j];
}

void multifactor(float** res, float** mat, nSize matSize, float factor)// 矩阵乘以系数
{
	int i,j;
	for(i=0;i<matSize.r;i++)
		for(j=0;j<matSize.c;j++)
			res[i][j]=mat[i][j]*factor;
}

float summat(float** mat,nSize matSize) // 矩阵各元素的和
{
	float sum=0.0;
	int i,j;
	for(i=0;i<matSize.r;i++)
		for(j=0;j<matSize.c;j++)
			sum=sum+mat[i][j];
	return sum;
}